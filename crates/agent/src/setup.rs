//! Setting a machine up for unattended access, and taking it down again:
//! the commands an administrator runs.

use anyhow::{Context, Result, bail};
use nearhand_transport::{Fingerprint, Identity};

use crate::access::{MIN_LENGTH, Stored};
use crate::enroll::{self, Outcome};
use crate::machine;

pub struct Install {
    /// `host:port`, `host` for port 443, or an IP address.
    pub server: String,
    pub server_fingerprint: Fingerprint,
    pub password: Option<String>,
    pub bitrate_kbps: u32,
    /// An enrollment token, to join the server's managed devices.
    pub token: Option<String>,
    /// The name to list this computer under, instead of its computer name.
    pub name: Option<String>,
}

/// Write the machine's configuration, make its key, and install and start
/// the service. Run again, it replaces the configuration but keeps the key,
/// and so the ID.
pub fn install(options: Install) -> Result<()> {
    let server = options.server.clone();
    let identity = configure(options)?;
    #[cfg(windows)]
    crate::service::install(&std::env::current_exe()?)?;

    println!("Installed. This computer's ID is {}.", identity.device_id());
    println!("Anyone with that ID and the access password can now control it,");
    println!("through {server} — keep the password safe.");
    Ok(())
}

/// Everything `install` does but the service: the configuration, the key,
/// and the policy that lets the agent send Ctrl+Alt+Del. The MSI runs this,
/// and registers the service itself.
pub fn configure(options: Install) -> Result<Identity> {
    supported()?;
    let server = options.server.trim().to_owned();
    if server.is_empty() {
        bail!("--server is needed: the server's address");
    }
    // The MSI passes an empty token, and password, when it was given none.
    let enrollment = options
        .token
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty())
        .map(|token| machine::Enrollment {
            token,
            name: options.name.filter(|name| !name.trim().is_empty()),
        });
    let password = options.password.filter(|password| !password.is_empty());
    // Enrolled, the server's grants let people in; a password is optional.
    // Otherwise it is the only way in.
    let access = match (password, &enrollment) {
        (Some(password), _) => Some(Stored::new(&password)?),
        (None, Some(_)) => None,
        (None, None) => Some(Stored::new(&new_password()?)?),
    };

    let dir = machine::dir();
    machine::prepare_dir(&dir)?;
    let mut config = machine::Config {
        server: machine::Server {
            address: server,
            fingerprint: options.server_fingerprint.to_string(),
        },
        bitrate_kbps: options.bitrate_kbps,
        access,
        managed: enrollment.is_some(),
        enrollment,
    };
    config.save(&dir)?;
    let identity =
        Identity::load_or_create(&machine::key_path(&dir)).context("creating the device key")?;

    if let Some(pending) = config.enrollment.clone() {
        match enroll::now(
            &config.server.address,
            options.server_fingerprint,
            &identity,
            &pending,
        )? {
            Outcome::Enrolled(_) => {
                config.enrollment = None;
                config.save(&dir)?;
                println!("Enrolled with the server.");
            }
            Outcome::Refused(refusal) => {
                config.enrollment = None;
                config.save(&dir)?;
                bail!("the server refused to enroll this computer: {refusal}");
            }
            Outcome::Later(error) => {
                println!("Could not reach the server to enroll ({error});");
                println!("the agent enrolls as soon as it can.");
            }
        }
    }

    #[cfg(windows)]
    if let Err(e) = crate::service::allow_secure_attention() {
        // Everything else works without it.
        println!("Note: Ctrl+Alt+Del from a viewer will not work: {e:#}");
    }
    Ok(identity)
}

/// Stop and remove the service; with `purge`, also the key and
/// configuration, and so the ID.
pub fn uninstall(purge: bool) -> Result<()> {
    supported()?;
    #[cfg(windows)]
    crate::service::uninstall()?;
    let dir = machine::dir();
    if purge {
        std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
        println!("Removed the service and {}.", dir.display());
    } else {
        println!("Removed the service. The key is kept in {},", dir.display());
        println!("so installing again keeps this computer's ID; --purge removes it.");
    }
    Ok(())
}

pub fn set_password(password: Option<String>, none: bool) -> Result<()> {
    supported()?;
    let dir = machine::dir();
    let mut config = machine::Config::load(&dir)?;
    if none && !config.managed {
        bail!(
            "this machine takes no grants from its server: without a password, no one could connect"
        );
    }
    config.access = if none {
        None
    } else {
        let password = match password {
            Some(password) => password,
            None => new_password()?,
        };
        Some(Stored::new(&password)?)
    };
    config.save(&dir)?;
    #[cfg(windows)]
    crate::service::restart()?;
    if none {
        println!("Access password removed: only grants from the server let anyone in.");
    } else {
        println!("Access password changed.");
    }
    Ok(())
}

pub fn status() -> Result<()> {
    let dir = machine::dir();
    #[cfg(windows)]
    match crate::service::state() {
        Some(state) => println!("service: {state:?}"),
        None => println!("service: not installed"),
    }
    if !machine::config_path(&dir).exists() {
        println!("server:  not installed");
    } else {
        match machine::Config::load(&dir) {
            Ok(config) => {
                println!("server:  {}", config.server.address);
                if config.enrollment.is_some() {
                    println!("         enrolling when it can be reached");
                }
                println!(
                    "access:  {}",
                    match (config.managed, config.access.is_some()) {
                        (true, true) => "grants from the server, or the access password",
                        (true, false) => "grants from the server only",
                        _ => "the access password only",
                    }
                );
            }
            Err(e) => println!("server:  unknown ({e:#})"),
        }
    }
    let key = machine::key_path(&dir);
    if key.exists() {
        let identity = Identity::load_or_create(&key).context("reading the device key")?;
        println!("ID:      {}", identity.device_id());
    } else {
        println!("ID:      none yet");
    }
    Ok(())
}

/// Installing needs the service manager and the machine-wide folder, both
/// for administrators only; and the service is Windows-only for now.
fn supported() -> Result<()> {
    if !cfg!(windows) {
        bail!("installing as a service is only supported on Windows so far");
    }
    if !crate::elevation::is_elevated() {
        bail!("run this as administrator");
    }
    Ok(())
}

/// Ask for a new access password, twice, without showing it.
fn new_password() -> Result<String> {
    let first = crate::prompt::hidden(&format!(
        "Access password (at least {MIN_LENGTH} characters): "
    ))?;
    let second = crate::prompt::hidden("Again: ")?;
    if first != second {
        bail!("the two passwords differ");
    }
    Ok(first)
}
