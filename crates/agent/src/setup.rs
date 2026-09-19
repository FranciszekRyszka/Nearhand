//! Setting a machine up for unattended access, and taking it down again:
//! the commands an administrator runs.

use std::net::SocketAddr;

use anyhow::{Context, Result, bail};
use nearhand_transport::{Fingerprint, Identity};

use crate::access::{MIN_LENGTH, Stored};
use crate::machine;

pub struct Install {
    pub server: SocketAddr,
    pub server_fingerprint: Fingerprint,
    pub password: Option<String>,
    pub bitrate_kbps: u32,
}

/// Write the machine's configuration, make its key, and install and start
/// the service. Run again, it replaces the configuration but keeps the key,
/// and so the ID.
pub fn install(options: Install) -> Result<()> {
    let server = options.server;
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
    let password = match options.password {
        Some(password) => password,
        None => new_password()?,
    };
    let access = Stored::new(&password)?;

    let dir = machine::dir();
    machine::prepare_dir(&dir)?;
    let config = machine::Config {
        server: machine::Server {
            address: options.server,
            fingerprint: options.server_fingerprint.to_string(),
        },
        bitrate_kbps: options.bitrate_kbps,
        access,
    };
    config.save(&dir)?;
    let identity =
        Identity::load_or_create(&machine::key_path(&dir)).context("creating the device key")?;

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

pub fn set_password(password: Option<String>) -> Result<()> {
    supported()?;
    let dir = machine::dir();
    let mut config = machine::Config::load(&dir)?;
    let password = match password {
        Some(password) => password,
        None => new_password()?,
    };
    config.access = Stored::new(&password)?;
    config.save(&dir)?;
    #[cfg(windows)]
    crate::service::restart()?;
    println!("Access password changed.");
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
            Ok(config) => println!("server:  {}", config.server.address),
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
