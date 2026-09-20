//! Portable quick-support mode: no install, no enrollment. The agent registers
//! with a server under the ID its key gives it, shows that ID and a one-time
//! password, and lets in a viewer who has both — and, when its window is
//! showing, whom the person at this machine allows.
//!
//! It never listens on a port. It keeps one connection to the server; when a
//! viewer asks for it, the agent opens its way through its firewall and NAT
//! to the viewer, and the viewer connects to the same socket the agent reaches
//! the server from (`nearhand_transport::rendezvous`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nearhand_core::proto::close;
use nearhand_transport::rendezvous::{Registration, Running, stay_registered};
use nearhand_transport::{Fingerprint, Identity, server_endpoint};
use quinn::Endpoint;

use crate::host::{Host, Server};
use crate::password::Password;
use crate::session::SessionConfig;

pub struct Options {
    pub server: SocketAddr,
    pub server_fingerprint: Fingerprint,
    pub key: PathBuf,
    pub bitrate_kbps: u32,
    /// Show the quick-support window, whose user allows each session; else
    /// print to the terminal, and let the password alone decide.
    pub window: bool,
}

/// Run until the window is closed, or, without one, until Ctrl+C.
pub fn run(options: Options) -> Result<()> {
    let identity = Identity::load_or_create(&options.key)
        .with_context(|| format!("loading the device key from {}", options.key.display()))?;
    let password = Arc::new(Password::new());
    let host = Host::new(options.window);

    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    let endpoint = {
        let _inside = runtime.enter();
        server_endpoint(unspecified_like(options.server), &identity)
            .context("opening the socket")?
    };
    let config = Arc::new(SessionConfig {
        bitrate_kbps: options.bitrate_kbps,
        gate: Some(password.clone()),
        grants: None,
        host: Some(host.clone()),
    });
    let id = identity.device_id();
    runtime.spawn(serve(
        endpoint.clone(),
        options.server,
        options.server_fingerprint,
        identity,
        config,
        host.clone(),
    ));

    if options.window {
        crate::window::run(id, password, host)?;
    } else {
        // Printed rather than logged: the person at this machine reads these
        // out.
        println!("ID:       {id}");
        println!("password: {}", password.current());
        runtime.block_on(async {
            let _ = tokio::signal::ctrl_c().await;
        });
        println!("stopping");
    }

    runtime.block_on(async {
        endpoint.close(close::NORMAL.into(), b"agent stopping");
        // Long enough to tell a viewer goodbye, not to hang on a lost one.
        let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    });
    Ok(())
}

/// Stay registered and serve viewers, until the runtime stops.
pub(crate) async fn serve(
    endpoint: Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: Identity,
    config: Arc<SessionConfig>,
    host: Arc<Host>,
) {
    let slot = crate::one_viewer();
    let events = |event| match event {
        // Viewers through the relay arrive on an endpoint of their own, one
        // per server connection; they share the one slot with direct viewers.
        Registration::Registered { relay } => {
            host.set_server(Server::Online);
            tokio::spawn(crate::accept_viewers(relay, config.clone(), slot.clone()));
        }
        Registration::Lost { error, .. } => host.set_server(Server::Unreachable { error }),
    };
    let running = Running::new(env!("CARGO_PKG_VERSION"));
    tokio::join!(
        crate::accept_viewers(endpoint.clone(), config.clone(), slot.clone()),
        stay_registered(
            &endpoint,
            server,
            server_fingerprint,
            &identity,
            &running,
            events,
        ),
    );
}

pub(crate) fn unspecified_like(addr: SocketAddr) -> SocketAddr {
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
