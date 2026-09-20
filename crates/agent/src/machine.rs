//! An installed agent's own files: its key and its configuration, kept
//! machine-wide rather than per user, in a folder only SYSTEM and
//! administrators can read. The key is the device's identity and the
//! configuration holds the access password's hash, so neither is for other
//! users of the machine to see.
//!
//! ```text
//! %ProgramData%\Nearhand\          (Windows)
//!     agent.toml                   server, its fingerprint, access password hash,
//!                                  an enrollment token not yet used
//!     device.key                   the device's Ed25519 key: its ID
//!     logs\                        the service's and the agent's logs
//!     updates\                     packages downloaded to update with
//! ```

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nearhand_transport::Fingerprint;
use serde::{Deserialize, Serialize};

use crate::access::Stored;

pub const DEFAULT_BITRATE_KBPS: u32 = 10_000;
/// The server's port when its address does not say.
pub const DEFAULT_SERVER_PORT: u16 = 443;

/// Where an installed agent keeps its files.
pub fn dir() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support")
    } else {
        PathBuf::from("/var/lib")
    };
    base.join(if cfg!(windows) || cfg!(target_os = "macos") {
        "Nearhand"
    } else {
        "nearhand"
    })
}

pub fn config_path(dir: &Path) -> PathBuf {
    dir.join("agent.toml")
}

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join("device.key")
}

pub fn log_dir(dir: &Path) -> PathBuf {
    dir.join("logs")
}

/// Where update packages are downloaded (`crate::update`).
pub fn updates_dir(dir: &Path) -> PathBuf {
    dir.join("updates")
}

/// `agent.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub server: Server,
    /// The most video bitrate to use.
    #[serde(default = "default_bitrate")]
    pub bitrate_kbps: u32,
    /// Anyone with this password may connect. None: grants only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Stored>,
    /// Installed with an enrollment token: grants signed by the server let
    /// people in. A machine installed with only a password never takes
    /// them, so the server alone cannot open it.
    #[serde(default)]
    pub managed: bool,
    /// Enrolling with the server, when installing could not reach it: the
    /// agent does it when it can, and then forgets the token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<Enrollment>,
    /// Ask for the access password as well as a grant, rather than instead
    /// of one. A server that was taken over can sign itself a grant for
    /// every machine enrolled with it, but it does not know their
    /// passwords (`docs/security.md`). Needs both a password and
    /// `managed`; off unless set.
    #[serde(default)]
    pub password_with_grant: bool,
    /// Install newer releases this machine's own server offers, signed by
    /// the project's release key (`crate::update`). On unless set false.
    #[serde(default = "yes")]
    pub updates: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// `host:port`, `host` alone for port 443, or an IP address.
    pub address: String,
    /// Hex, as the server prints it.
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    pub token: String,
    /// The name to list this computer under; its computer name if none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Where the server at `address` is now: `host:port`, `host` alone for port
/// 443, or an IP address, with or without a port. The agent looks names
/// up as it starts, so a server that moves is followed after a restart.
pub fn resolve(address: &str) -> Result<SocketAddr> {
    let address = address.trim();
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = address.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, DEFAULT_SERVER_PORT));
    }
    let with_port = match address.rsplit_once(':') {
        Some((_, port)) if port.parse::<u16>().is_ok() => address.to_owned(),
        _ => format!("{address}:{DEFAULT_SERVER_PORT}"),
    };
    let mut found: Vec<SocketAddr> = with_port
        .to_socket_addrs()
        .with_context(|| format!("looking up {address}"))?
        .collect();
    // IPv4 first: more networks route it, and the agent listens on one
    // family, the one it reaches the server over.
    found.sort_by_key(|a| a.is_ipv6());
    found
        .into_iter()
        .next()
        .with_context(|| format!("{address} has no address"))
}

fn default_bitrate() -> u32 {
    DEFAULT_BITRATE_KBPS
}

impl Config {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = config_path(dir);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let config: Self =
            toml::from_str(&text).with_context(|| format!("reading {}", path.display()))?;
        config.server_fingerprint()?;
        Ok(config)
    }

    /// Write it, whole or not at all: aside first, then renamed into place.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let path = config_path(dir);
        let text = format!(
            "# Written by `nearhand-agent install`; `nearhand-agent set-password`\n\
             # changes the password.\n\n{}",
            toml::to_string(self).context("writing the configuration")?
        );
        let partial = path.with_extension("partial");
        std::fs::write(&partial, text).with_context(|| format!("writing {}", partial.display()))?;
        std::fs::rename(&partial, &path).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    pub fn server_fingerprint(&self) -> Result<Fingerprint> {
        self.server
            .fingerprint
            .parse()
            .context("the server fingerprint in agent.toml")
    }
}

/// Create `dir` if needed and make it readable by SYSTEM and administrators
/// only. Files created in it afterwards inherit that.
pub fn prepare_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(windows)]
    restrict(dir)?;
    std::fs::create_dir_all(log_dir(dir))?;
    Ok(())
}

/// SYSTEM and Administrators, full control, inherited by everything inside;
/// nothing inherited from above.
#[cfg(windows)]
const PRIVATE: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

#[cfg(windows)]
fn restrict(dir: &Path) -> Result<()> {
    set_dacl(dir, PRIVATE)
}

#[cfg(windows)]
fn set_dacl(path: &Path, sddl: &str) -> Result<()> {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    use windows::core::{BOOL, HSTRING};

    let sddl = HSTRING::from(sddl);
    let path = HSTRING::from(path.as_os_str());
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: the descriptor is allocated by Windows, freed with LocalFree
    // below, and the ACL pointer into it is used only before that.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .context("building the folder's permissions")?;
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let got = GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted);
        let result = got.map_err(anyhow::Error::from).and_then(|()| {
            SetNamedSecurityInfoW(
                &path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
            .ok()
            .map_err(anyhow::Error::from)
        });
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        result.context("setting the folder's permissions")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nearhand-machine-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn config() -> Config {
        Config {
            server: Server {
                address: "desk.example.com:443".into(),
                fingerprint: "ab".repeat(32),
            },
            bitrate_kbps: 8000,
            access: Some(Stored {
                iterations: 600_000,
                salt: "00".repeat(16),
                hash: "11".repeat(32),
            }),
            enrollment: Some(Enrollment {
                token: "nhe_00ff".into(),
                name: None,
            }),
            managed: true,
            password_with_grant: false,
            updates: true,
        }
    }

    #[test]
    fn server_addresses_take_many_forms() {
        let port = |a: &str| resolve(a).expect(a).port();
        assert_eq!(
            resolve("203.0.113.10:4433").expect("ip"),
            "203.0.113.10:4433".parse().expect("addr")
        );
        assert_eq!(port("203.0.113.10"), 443);
        assert_eq!(
            resolve("[2001:db8::1]:8443").expect("v6"),
            "[2001:db8::1]:8443".parse().expect("addr")
        );
        assert_eq!(port("2001:db8::1"), 443);
        assert_eq!(port("localhost"), 443);
        assert_eq!(port("localhost:4433"), 4433);
        assert!(resolve("localhost").expect("name").ip().is_loopback());
        assert!(resolve("no-such-host.invalid").is_err());
    }

    #[test]
    fn an_earlier_configuration_still_loads() {
        // As written before servers could be named and devices enrolled.
        let old = "[server]\naddress = \"203.0.113.10:443\"\nfingerprint = \"{fp}\"\n\
                   [access]\niterations = 600000\nsalt = \"00\"\nhash = \"11\"\n"
            .replace("{fp}", &"ab".repeat(32));
        let parsed: Config = toml::from_str(&old).expect("parse");
        assert_eq!(parsed.server.address, "203.0.113.10:443");
        assert_eq!(parsed.enrollment, None);
        assert!(
            !parsed.managed,
            "no grants for a machine installed before them"
        );
        assert!(
            !toml::to_string(&parsed)
                .expect("write")
                .contains("enrollment")
        );
    }

    #[test]
    fn the_configuration_roundtrips_and_is_readable() {
        let dir = scratch("roundtrip");
        config().save(&dir).expect("save");
        assert_eq!(Config::load(&dir).expect("load"), config());
        let text = std::fs::read_to_string(config_path(&dir)).expect("read");
        assert!(
            text.contains("[server]") && text.contains("[access]"),
            "{text}"
        );
        assert!(!config_path(&dir).with_extension("partial").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_fingerprint_is_caught_on_load() {
        let dir = scratch("fingerprint");
        let mut bad = config();
        bad.server.fingerprint = "not hex".into();
        bad.save(&dir).expect("save");
        assert!(Config::load(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_bitrate_has_a_default() {
        let text = toml::to_string(&config())
            .expect("serialize")
            .replace("bitrate_kbps = 8000\n", "");
        let parsed: Config = toml::from_str(&text).expect("parse");
        assert_eq!(parsed.bitrate_kbps, DEFAULT_BITRATE_KBPS);
    }

    /// The folder's permissions come out as asked. Run against a scratch
    /// folder this process owns, so it can put them back and clean up.
    #[cfg(windows)]
    #[test]
    fn the_folder_is_closed_to_everyone_but_system_and_administrators() {
        let dir = scratch("acl");
        restrict(&dir).expect("restrict");
        let sddl = dacl_of(&dir);
        assert!(sddl.starts_with("D:P"), "not protected: {sddl}");
        assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"), "{sddl}");
        assert_eq!(sddl.matches("(A;").count(), 2, "only two grants: {sddl}");
        // As its owner, this process may still change it back.
        set_dacl(&dir, "D:(A;OICI;FA;;;WD)").expect("reopen");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    fn dacl_of(path: &Path) -> String {
        use windows::Win32::Foundation::{HLOCAL, LocalFree};
        use windows::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
            SDDL_REVISION_1, SE_FILE_OBJECT,
        };
        use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
        use windows::core::{HSTRING, PWSTR};

        let path = HSTRING::from(path.as_os_str());
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut text = PWSTR::null();
        // SAFETY: both buffers come from Windows and are freed here.
        unsafe {
            GetNamedSecurityInfoW(
                &path,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut descriptor,
            )
            .ok()
            .expect("read permissions");
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
            .expect("describe permissions");
            let sddl = text.to_string().expect("utf-16");
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            sddl
        }
    }
}
