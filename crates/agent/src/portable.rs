//! Portable quick-support mode: no install, no enrollment. The agent registers
//! with a server under the ID its key gives it, shows that ID and a one-time
//! password, and lets in a viewer who has both.
//!
//! It never listens on a port. It keeps one connection to the server; when a
//! viewer asks for it, the server passes on the viewer's addresses, the agent
//! sends a packet to each — which is what lets the viewer's connection through
//! this machine's firewall — and the viewer connects to the same socket the
//! agent reaches the server from.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nearhand_core::proto::close;
use nearhand_core::rendezvous::{FromServer, ToServer};
use nearhand_transport::{
    Fingerprint, Identity, connect_server, local_ip_toward, punch, recv_message, send_message,
    server_endpoint,
};
use quinn::Endpoint;

use crate::password::Password;
use crate::session::SessionConfig;

/// How long the connection attempts that open the way are kept up: QUIC
/// resends them meanwhile, in case the first packet is lost.
const PUNCH_HOLD: Duration = Duration::from_secs(5);
/// Time for the punches to leave before the viewer is told to come.
const PUNCH_HEAD_START: Duration = Duration::from_millis(20);
/// Retrying a lost server connection: from this, doubling, up to the max.
const RECONNECT_FIRST: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);

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
    tokio::select! {
        () = crate::accept_viewers(endpoint.clone(), config) => {}
        () = stay_registered(&endpoint, &options, &identity) => {}
        _ = tokio::signal::ctrl_c() => println!("stopping"),
    }
    endpoint.close(close::NORMAL.into(), b"agent stopping");
    endpoint.wait_idle().await;
    Ok(())
}

/// Keep a registration with the server, reconnecting whenever it is lost.
async fn stay_registered(endpoint: &Endpoint, options: &Options, identity: &Identity) {
    let mut wait = RECONNECT_FIRST;
    loop {
        match register(endpoint, options, identity).await {
            // Registered for a while and then lost: reconnect promptly.
            Ok(()) => {
                tracing::info!("server connection ended; reconnecting");
                wait = RECONNECT_FIRST;
            }
            Err(e) => {
                tracing::warn!(error = %format!("{e:#}"), retry_in = ?wait, "server unreachable")
            }
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RECONNECT_MAX);
    }
}

async fn register(endpoint: &Endpoint, options: &Options, identity: &Identity) -> Result<()> {
    let conn = connect_server(
        endpoint,
        options.server,
        options.server_fingerprint,
        Some(identity),
    )
    .await
    .with_context(|| format!("connecting to {}", options.server))?;
    let (mut send, mut recv) = conn.open_bi().await?;

    let port = endpoint.local_addr()?.port();
    let addresses: Vec<SocketAddr> = local_ip_toward(options.server)
        .map(|ip| SocketAddr::new(ip, port))
        .into_iter()
        .collect();
    send_message(&mut send, &ToServer::Register { addresses }).await?;
    match recv_message::<FromServer>(&mut recv).await? {
        Some(FromServer::Registered { id, observed }) => {
            tracing::info!(%id, %observed, "registered with the server");
        }
        Some(FromServer::Refused(refusal)) => bail!("the server refused: {refusal}"),
        other => bail!("unexpected answer from the server: {other:?}"),
    }

    while let Some(message) = recv_message::<FromServer>(&mut recv).await? {
        match message {
            FromServer::Incoming { session, addresses } => {
                tracing::info!(session, ?addresses, "a viewer is coming");
                for address in addresses {
                    let endpoint = endpoint.clone();
                    tokio::spawn(async move { punch(&endpoint, address, PUNCH_HOLD).await });
                }
                tokio::time::sleep(PUNCH_HEAD_START).await;
                send_message(&mut send, &ToServer::Ready { session }).await?;
            }
            other => tracing::debug!(?other, "unexpected from the server"),
        }
    }
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
