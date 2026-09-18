//! Portable quick-support mode: no install, no enrollment. The agent registers
//! with a server under the ID its key gives it, shows that ID and a one-time
//! password, and lets in a viewer who has both.
//!
//! It never listens on a port. It keeps one connection to the server; when a
//! viewer asks for it, the agent opens its way through its firewall and NAT
//! to the viewer, and the viewer connects to the same socket the agent reaches
//! the server from (`nearhand_transport::rendezvous`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use nearhand_core::proto::close;
use nearhand_transport::rendezvous::stay_registered;
use nearhand_transport::{Fingerprint, Identity, server_endpoint};

use crate::password::Password;
use crate::session::SessionConfig;

pub struct Options {
    pub server: SocketAddr,
    pub server_fingerprint: Fingerprint,
    pub key: PathBuf,
    pub bitrate_kbps: u32,
}

pub async fn run(options: Options) -> Result<()> {
    let identity = Identity::load_or_create(&options.key)
        .with_context(|| format!("loading the device key from {}", options.key.display()))?;
    let bind = unspecified_like(options.server);
    let endpoint = server_endpoint(bind, &identity).context("opening the socket")?;
    let password = Arc::new(Password::new());

    // Printed rather than logged: the person at this machine reads these out.
    println!("ID:       {}", identity.device_id());
    println!("password: {}", password.current());

    let config = Arc::new(SessionConfig {
        bitrate_kbps: options.bitrate_kbps,
        password: Some(password),
    });
    let slot = crate::one_viewer();
    // Viewers through the relay arrive on an endpoint of their own, one per
    // server connection; they share the one slot with direct viewers.
    let relayed = |relay: quinn::Endpoint| {
        tokio::spawn(crate::accept_viewers(relay, config.clone(), slot.clone()));
    };
    tokio::select! {
        () = crate::accept_viewers(endpoint.clone(), config.clone(), slot.clone()) => {}
        () = stay_registered(&endpoint, options.server, options.server_fingerprint, &identity, relayed) => {}
        _ = tokio::signal::ctrl_c() => println!("stopping"),
    }
    endpoint.close(close::NORMAL.into(), b"agent stopping");
    endpoint.wait_idle().await;
    Ok(())
}

fn unspecified_like(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    }
}

/// Where this user's device key lives. Per user, because a portable agent runs
/// as whoever started it; the M3 service keeps its own, machine-wide.
pub fn default_key_path() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
    };
    base.unwrap_or_else(|| PathBuf::from("."))
        .join("Nearhand")
        .join("device.key")
}
