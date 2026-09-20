//! Keeping an installed agent up to date, from its own server.
//!
//! The agent asks its server now and then whether it offers a newer release
//! (`nearhand_core::rendezvous::ToServer::Update`). It installs one only if
//! the release key built into it signed the release, the package is the one
//! signed, and the version is newer than the one running — so a server
//! chooses when its agents update and to which of the project's releases,
//! and can do nothing else to them (`docs/security.md`).
//!
//! Installing restarts the service, and so ends any session: it waits for
//! the machine to be free. The installer is started detached, because it
//! stops the service — and with it this agent — while it works.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use nearhand_core::release::{self, Release, Version};
use nearhand_transport::rendezvous::check_update;
use nearhand_transport::{Fingerprint, Identity, release as signing};
use quinn::Endpoint;

use crate::host::Host;

/// How long after starting the first check is: long enough not to add to
/// the rush when many machines come back at once.
const FIRST_CHECK: Duration = Duration::from_secs(5 * 60);
/// Between checks after that.
const EVERY: Duration = Duration::from_secs(6 * 3600);
/// When a check failed, or a session was on, or the server was busy.
const RETRY: Duration = Duration::from_secs(15 * 60);
/// The largest package this will fetch. The release key signs the size, so
/// this only bounds what a release could ask of a machine's memory —
/// agent installers are a few MB.
const MAX_PACKAGE: u64 = 256 * 1024 * 1024;

/// What this agent is, for the server to answer about.
pub fn this_version() -> Version {
    env!("CARGO_PKG_VERSION").parse().unwrap_or(Version {
        major: 0,
        minor: 0,
        patch: 0,
    })
}

/// The platform this build updates for, if releases cover it.
pub fn this_platform() -> Option<&'static str> {
    cfg!(all(windows, target_arch = "x86_64")).then_some(release::WINDOWS_X86_64)
}

pub struct Updates {
    pub endpoint: Endpoint,
    pub server: std::net::SocketAddr,
    pub server_fingerprint: Fingerprint,
    pub identity: Identity,
    /// Where packages are downloaded: the installation's `updates`.
    pub dir: PathBuf,
    /// Where the installer's log goes.
    pub log: PathBuf,
    /// Asked whether a session is on; updating waits for none.
    pub host: std::sync::Arc<Host>,
    /// The release key releases must be signed by:
    /// `nearhand_core::release::KEY`, except in tests.
    pub key: [u8; 32],
    /// What installs a package; `msiexec` unless a test stands in for it.
    pub installer: Option<Installer>,
}

/// Runs an installer package.
pub type Installer = Box<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// Check for a newer release, and install it, for as long as the agent
/// runs.
pub async fn keep_updated(updates: Updates) {
    let Some(platform) = this_platform() else {
        tracing::debug!("no releases for this platform; not updating");
        return;
    };
    let mut wait = FIRST_CHECK;
    loop {
        tokio::time::sleep(wait).await;
        wait = match updates.once(platform).await {
            Ok(Checked::UpToDate) => EVERY,
            Ok(Checked::Installing) => {
                // The installer stops the service, and this agent with it.
                tracing::info!("an update is being installed");
                return;
            }
            Ok(Checked::NotNow) => RETRY,
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), "could not check for updates");
                RETRY
            }
        };
    }
}

enum Checked {
    UpToDate,
    /// A session is on, or the server is busy: later.
    NotNow,
    Installing,
}

impl Updates {
    async fn once(&self, platform: &str) -> Result<Checked> {
        // An update restarts the service: never during a session.
        if self.host.view().session.is_some() {
            return Ok(Checked::NotNow);
        }
        let current = this_version();
        let offered = check_update(
            &self.endpoint,
            self.server,
            self.server_fingerprint,
            &self.identity,
            release::AGENT,
            platform,
            current,
        )
        .await;
        let offered = match offered {
            Ok(Some(offered)) => offered,
            Ok(None) => return Ok(Checked::UpToDate),
            Err(nearhand_transport::Error::Refused(nearhand_core::rendezvous::Refusal::Busy)) => {
                return Ok(Checked::NotNow);
            }
            Err(e) => return Err(e.into()),
        };
        // Checked before a byte is fetched: the size below comes from here.
        let release = signing::verify(&offered.signed, &self.key)
            .map_err(|e| anyhow!("{e}"))
            .context("the release offered is not the project's")?;
        suitable(&release, platform, current)?;
        tracing::info!(version = %release.version, bytes = release.size, "fetching an update");
        let package = offered
            .fetch(release.size)
            .await
            .context("fetching the update")?;
        signing::check_package(&release, &package)
            .map_err(|e| anyhow!("{e}"))
            .context("the package is not the one the release describes")?;

        // Nothing has touched this machine until here.
        if self.host.view().session.is_some() {
            return Ok(Checked::NotNow);
        }
        let path = self.write(&release, &package).await?;
        match &self.installer {
            Some(installer) => installer(&path)?,
            None => self.install(&path)?,
        }
        Ok(Checked::Installing)
    }

    /// Put the package where the installer can read it, under a temporary
    /// name first.
    async fn write(&self, release: &Release, package: &[u8]) -> Result<PathBuf> {
        tokio::fs::create_dir_all(&self.dir)
            .await
            .with_context(|| format!("creating {}", self.dir.display()))?;
        let path = self
            .dir
            .join(format!("nearhand-agent-{}.msi", release.version));
        let partial = path.with_extension("partial");
        tokio::fs::write(&partial, package)
            .await
            .with_context(|| format!("writing {}", partial.display()))?;
        tokio::fs::rename(&partial, &path)
            .await
            .with_context(|| format!("renaming {}", partial.display()))?;
        Ok(path)
    }

    /// Start the installer and leave it to it: it stops the service, and
    /// this process with it, then starts the new agent.
    #[cfg(windows)]
    fn install(&self, package: &Path) -> Result<()> {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;

        if let Some(dir) = self.log.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let started = std::process::Command::new("msiexec.exe")
            .args(["/i".as_ref(), package.as_os_str()])
            .args(["/qn", "/norestart", "/l*v"])
            .arg(&self.log)
            .creation_flags(DETACHED_PROCESS | CREATE_NO_WINDOW)
            .spawn()
            .context("starting msiexec")?;
        tracing::info!(
            installer = started.id(),
            package = %package.display(),
            log = %self.log.display(),
            "installing the update"
        );
        Ok(())
    }

    #[cfg(not(windows))]
    fn install(&self, _package: &Path) -> Result<()> {
        bail!("installing updates is for Windows so far")
    }
}

/// Whether a release is one this agent may install: the right product and
/// platform, a package it can install, and newer than what runs.
fn suitable(release: &Release, platform: &str, current: Version) -> Result<()> {
    if release.product != release::AGENT {
        bail!("the release is for {}, not the agent", release.product);
    }
    if release.platform != platform {
        bail!("the release is for {}, not {platform}", release.platform);
    }
    if release.package != release::Package::Msi {
        bail!("the release is not an installer this agent can run");
    }
    if release.version <= current {
        bail!(
            "the release is {}, and {current} is running",
            release.version
        );
    }
    if release.size > MAX_PACKAGE {
        bail!(
            "the release is {} bytes: too large to install",
            release.size
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nearhand_core::release::{Package, WINDOWS_X86_64};

    fn release(version: &str) -> Release {
        Release {
            product: release::AGENT.into(),
            version: version.parse().expect("version"),
            platform: WINDOWS_X86_64.into(),
            package: Package::Msi,
            sha256: [0; 32],
            size: 10,
        }
    }

    fn version(s: &str) -> Version {
        s.parse().expect("version")
    }

    #[test]
    fn only_a_newer_release_for_this_agent_is_installed() {
        let current = version("0.2.0");
        suitable(&release("0.3.0"), WINDOWS_X86_64, current).expect("newer");
        for (release, reason) in [
            (release("0.2.0"), "the same version"),
            (release("0.1.9"), "older"),
            (
                Release {
                    product: "nearhand-server".into(),
                    ..release("0.3.0")
                },
                "another product",
            ),
            (
                Release {
                    platform: "macos-aarch64".into(),
                    ..release("0.3.0")
                },
                "another platform",
            ),
        ] {
            assert!(
                suitable(&release, WINDOWS_X86_64, current).is_err(),
                "{reason}"
            );
        }
    }

    #[test]
    fn this_build_knows_what_it_is() {
        assert_eq!(this_version().to_string(), env!("CARGO_PKG_VERSION"));
        assert_eq!(this_platform().is_some(), cfg!(windows));
    }

    // --- The whole way: ask, fetch, check, install -----------------------

    use nearhand_core::rendezvous::{FromServer, ToServer};
    use nearhand_transport::{recv_message, rendezvous_endpoint, send_message};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A stand-in server: it offers `signed` to whoever asks, and sends
    /// `package` to whoever fetches.
    fn stands_in(
        signed: nearhand_core::release::SignedRelease,
        package: Vec<u8>,
    ) -> (
        std::net::SocketAddr,
        Fingerprint,
        tokio::task::JoinHandle<()>,
    ) {
        let identity = Identity::generate().expect("server key");
        let fingerprint = identity.fingerprint();
        let endpoint =
            rendezvous_endpoint(([127, 0, 0, 1], 0).into(), &identity).expect("server endpoint");
        let address = endpoint.local_addr().expect("address");
        let serving = tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let (signed, package) = (signed.clone(), package.clone());
                tokio::spawn(async move {
                    let conn = incoming.await.expect("handshake");
                    let (mut send, mut recv) = conn.accept_bi().await.expect("stream");
                    let asked = recv_message::<ToServer>(&mut recv).await.expect("asked");
                    assert!(matches!(asked, Some(ToServer::Update { .. })), "{asked:?}");
                    send_message(&mut send, &FromServer::Offered(Some(signed)))
                        .await
                        .expect("offer");
                    if let Ok(Some(ToServer::Fetch)) = recv_message::<ToServer>(&mut recv).await {
                        send.write_all(&package).await.expect("send the package");
                        let _ = send.finish();
                    }
                    conn.closed().await;
                });
            }
        });
        (address, fingerprint, serving)
    }

    /// A release signed by a key of the test's own, and the package.
    fn signed_release(
        version: &str,
        package: &[u8],
        mutate: impl FnOnce(&mut Release),
    ) -> ([u8; 32], nearhand_core::release::SignedRelease) {
        let (private, public) = signing::generate_key().expect("key");
        let mut release = Release {
            product: release::AGENT.into(),
            version: version.parse().expect("version"),
            platform: WINDOWS_X86_64.into(),
            package: Package::Msi,
            sha256: signing::sha256(package),
            size: package.len() as u64,
        };
        mutate(&mut release);
        (public, signing::sign(&private, &release).expect("sign"))
    }

    struct Checking {
        updates: Updates,
        installed: Arc<std::sync::Mutex<Vec<PathBuf>>>,
        attempts: Arc<AtomicUsize>,
        _dir: Scratch,
    }

    /// A folder for one test, removed with it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("nearhand-update-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn checking(key: [u8; 32], host: Arc<Host>) -> Checking {
        let dir = Scratch::new();
        let installed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let (seen, count) = (installed.clone(), attempts.clone());
        let identity = Identity::generate().expect("agent key");
        let endpoint = nearhand_transport::server_endpoint(([127, 0, 0, 1], 0).into(), &identity)
            .expect("agent endpoint");
        Checking {
            updates: Updates {
                endpoint,
                server: ([127, 0, 0, 1], 0).into(),
                server_fingerprint: Fingerprint::from_bytes([0; 32]),
                identity,
                dir: dir.path().join("updates"),
                log: dir.path().join("update.log"),
                host,
                key,
                installer: Some(Box::new(move |package: &Path| {
                    count.fetch_add(1, Ordering::Relaxed);
                    seen.lock().expect("lock").push(package.to_path_buf());
                    Ok(())
                })),
            },
            installed,
            attempts,
            _dir: dir,
        }
    }

    #[tokio::test]
    async fn a_newer_signed_release_is_fetched_checked_and_installed() {
        let package = b"the next agent, in an installer".to_vec();
        let newer = format!("{}.0.0", this_version().major + 1);
        let (key, signed) = signed_release(&newer, &package, |_| {});
        let (address, fingerprint, serving) = stands_in(signed, package.clone());

        let mut checking = checking(key, Host::new(false));
        checking.updates.server = address;
        checking.updates.server_fingerprint = fingerprint;
        let outcome = checking.updates.once(WINDOWS_X86_64).await.expect("check");
        assert!(matches!(outcome, Checked::Installing));

        let installed = checking.installed.lock().expect("lock").clone();
        assert_eq!(installed.len(), 1, "installed once");
        assert_eq!(std::fs::read(&installed[0]).expect("package"), package);
        assert!(
            installed[0].to_string_lossy().contains(&newer),
            "named for its version: {}",
            installed[0].display()
        );
        serving.abort();
    }

    /// A server offering `signed`, and sending `package` for it, gets
    /// nothing installed: `what` says why not.
    async fn refused(
        what: &str,
        key: [u8; 32],
        signed: nearhand_core::release::SignedRelease,
        package: Vec<u8>,
    ) {
        let (address, fingerprint, serving) = stands_in(signed, package);
        let mut checking = checking(key, Host::new(false));
        checking.updates.server = address;
        checking.updates.server_fingerprint = fingerprint;
        let outcome = checking.updates.once(WINDOWS_X86_64).await;
        assert!(outcome.is_err(), "{what} was accepted");
        assert_eq!(checking.attempts.load(Ordering::Relaxed), 0, "{what}");
        serving.abort();
    }

    #[tokio::test]
    async fn nothing_is_installed_that_does_not_check_out() {
        let package = b"the next agent, in an installer".to_vec();
        let newer = format!("{}.0.0", this_version().major + 1);

        // Signed by another key than the one this agent trusts.
        let (_, signed) = signed_release(&newer, &package, |_| {});
        let (other, _) = signing::generate_key().expect("key");
        let stranger = signing::public_key(&other).expect("public");
        refused("another key", stranger, signed, package.clone()).await;

        // The package is not the one the release describes.
        let (key, signed) = signed_release(&newer, b"something else entirely", |_| {});
        refused("another package", key, signed, package.clone()).await;

        // Older than what runs.
        let (key, signed) = signed_release("0.0.0", &package, |_| {});
        refused("an older version", key, signed, package.clone()).await;

        // For another platform.
        let (key, signed) = signed_release(&newer, &package, |release| {
            release.platform = "macos-aarch64".into();
        });
        refused("another platform", key, signed, package).await;
    }

    /// A session must not be cut short by an installer.
    #[tokio::test]
    async fn nothing_is_installed_during_a_session() {
        let package = b"the next agent".to_vec();
        let newer = format!("{}.0.0", this_version().major + 1);
        let (key, signed) = signed_release(&newer, &package, |_| {});
        let (address, fingerprint, serving) = stands_in(signed, package);

        let host = Host::new(false);
        let _session = host.session_started("a viewer", || {});
        let mut checking = checking(key, host);
        checking.updates.server = address;
        checking.updates.server_fingerprint = fingerprint;
        let outcome = checking.updates.once(WINDOWS_X86_64).await.expect("check");
        assert!(matches!(outcome, Checked::NotNow));
        assert_eq!(checking.attempts.load(Ordering::Relaxed), 0);
        serving.abort();
    }
}
