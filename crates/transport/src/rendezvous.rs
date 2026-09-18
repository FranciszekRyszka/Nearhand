//! The clients' side of the server protocol (`nearhand_core::rendezvous`): an
//! agent staying registered and opening its way to each viewer, and a viewer
//! finding a device by ID and reaching it.
//!
//! ## Getting through NATs
//!
//! A NAT, like any stateful firewall, lets a packet in only from an address
//! something inside has sent to. Agent and viewer both reach the server from
//! the socket they later use for each other, so the server sees the public
//! address and port each one's NAT maps that socket to, and passes each on to
//! the other. The agent sends a packet to the viewer's, which opens its own
//! NAT to the viewer; then the viewer connects to the agent's, which opens the
//! viewer's NAT to the agent's answer. The viewer tries every address it was
//! given at once, and the first to answer wins: the local one when both are
//! on the same network, the public one across the internet.
//!
//! This relies on the agent's NAT keeping one public port for a socket, whoever
//! it talks to — "endpoint-independent mapping", which most home routers do.
//! A NAT that picks a new port for each destination (a "symmetric" one, common
//! on mobile networks and in offices) makes the port the server saw useless to
//! anyone else. Which pairs of NATs a direct connection gets through is a
//! table in `docs/protocol.md`, and a test in the server crate. Where there is
//! no direct path, the relay carries the session instead.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use nearhand_core::ALPN;
use nearhand_core::proto::close;
use nearhand_core::rendezvous::{DeviceId, FromServer, ToServer};
use quinn::{Connection, Endpoint};

use crate::{
    Error, Fingerprint, Identity, Result, SERVER_NAME, client_config, connect, connect_server,
    recv_message, send_message,
};

/// How long the connection attempts that open the way are kept up: QUIC
/// resends them meanwhile, in case the first packet is lost.
const PUNCH_HOLD: Duration = Duration::from_secs(5);
/// Time for the punches to leave before the viewer is told to come.
const PUNCH_HEAD_START: Duration = Duration::from_millis(20);
/// Retrying a lost server connection: from this, doubling, up to the max.
const RECONNECT_FIRST: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// How long each of a device's addresses gets to answer a viewer.
pub const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Keep this agent registered with the server, reconnecting whenever the
/// connection is lost, and open the way to every viewer the server
/// introduces. Never returns; drop it to stop.
///
/// `endpoint` must be the one that accepts viewers: its socket is the one the
/// server sees, and so the one viewers are sent to.
pub async fn stay_registered(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
) {
    let mut wait = RECONNECT_FIRST;
    loop {
        match register(endpoint, server, server_fingerprint, identity).await {
            // Registered for a while and then lost: reconnect promptly.
            Ok(()) => {
                tracing::info!("server connection ended; reconnecting");
                wait = RECONNECT_FIRST;
            }
            Err(e) => tracing::warn!(error = %e, retry_in = ?wait, "server unreachable"),
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RECONNECT_MAX);
    }
}

async fn register(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
) -> Result<()> {
    let conn = connect_server(endpoint, server, server_fingerprint, Some(identity)).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let addresses = own_addresses(endpoint, server);
    send_message(&mut send, &ToServer::Register { addresses }).await?;
    match recv_message::<FromServer>(&mut recv).await? {
        Some(FromServer::Registered { id, observed }) => {
            tracing::info!(%id, %observed, "registered with the server");
        }
        Some(FromServer::Refused(refusal)) => return Err(Error::Refused(refusal)),
        other => return Err(Error::Unexpected(format!("{other:?}"))),
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

/// Ask the server to introduce this viewer to device `id`, then connect to it
/// directly, pinned to the key the server reports for it.
///
/// Everything goes out from `endpoint`'s one socket: the address the server
/// sees is the one the agent opens its way to.
pub async fn find(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    id: DeviceId,
) -> Result<Connection> {
    let introducer = connect_server(endpoint, server, server_fingerprint, None).await?;
    let (mut send, mut recv) = introducer.open_bi().await?;
    let addresses = own_addresses(endpoint, server);
    send_message(&mut send, &ToServer::Connect { id, addresses }).await?;
    let answer = recv_message::<FromServer>(&mut recv).await;
    introducer.close(close::NORMAL.into(), b"introduced");

    let (fingerprint, addresses) = match answer? {
        Some(FromServer::Peer {
            fingerprint,
            addresses,
        }) => (Fingerprint::from_bytes(fingerprint), addresses),
        Some(FromServer::Refused(refusal)) => return Err(Error::Refused(refusal)),
        other => return Err(Error::Unexpected(format!("{other:?}"))),
    };
    // Not a security check — ten digits are easily matched on purpose — but
    // it catches a server that mixes up its devices.
    if fingerprint.device_id() != id {
        return Err(Error::Unexpected(
            "the server answered with another device's key".into(),
        ));
    }
    tracing::info!(?addresses, "introduced; connecting");
    race(endpoint, &addresses, fingerprint).await
}

/// Try every address at once and keep the first connection made.
async fn race(
    endpoint: &Endpoint,
    addresses: &[SocketAddr],
    fingerprint: Fingerprint,
) -> Result<Connection> {
    let mut attempts = tokio::task::JoinSet::new();
    for &address in addresses {
        let endpoint = endpoint.clone();
        attempts.spawn(async move {
            let result = tokio::time::timeout(
                PEER_CONNECT_TIMEOUT,
                connect(&endpoint, address, fingerprint),
            )
            .await;
            (address, result)
        });
    }
    let mut failures = Vec::new();
    while let Some(joined) = attempts.join_next().await {
        match joined {
            Ok((_, Ok(Ok(conn)))) => {
                attempts.abort_all();
                return Ok(conn);
            }
            Ok((address, Ok(Err(e)))) => failures.push(format!("{address}: {e}")),
            Ok((address, Err(_))) => failures.push(format!("{address}: no answer")),
            Err(e) => failures.push(e.to_string()),
        }
    }
    Err(Error::Unreachable(failures.join("; ")))
}

/// Open this endpoint's way to `target` through the local firewall and NAT,
/// by sending it a packet.
///
/// The packet is the first of a connection attempt that will never complete:
/// what matters is that it left. The attempt is kept alive for `hold`, so QUIC
/// resends it in the meantime.
async fn punch(endpoint: &Endpoint, target: SocketAddr, hold: Duration) {
    let Ok(config) = client_config(Fingerprint::from_bytes([0; 32]), ALPN, None) else {
        return;
    };
    let Ok(connecting) = endpoint.connect_with(config, target, SERVER_NAME) else {
        return;
    };
    let _ = tokio::time::timeout(hold, connecting).await;
}

/// Where others on this machine's own network can reach `endpoint`. The
/// server adds the address it sees, which is where everyone else can.
fn own_addresses(endpoint: &Endpoint, server: SocketAddr) -> Vec<SocketAddr> {
    let Ok(local) = endpoint.local_addr() else {
        return Vec::new();
    };
    let ip = if local.ip().is_unspecified() {
        local_ip_toward(server)
    } else {
        Some(local.ip())
    };
    ip.map(|ip| SocketAddr::new(ip, local.port()))
        .into_iter()
        .collect()
}

/// The local address this machine would use to reach `remote`. No packet is
/// sent.
fn local_ip_toward(remote: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if remote.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    socket.local_addr().ok().map(|a| a.ip())
}

/// Whether `address` belongs to a private network: a connection to it did
/// not cross the internet.
pub fn is_local(address: SocketAddr) -> bool {
    match address.ip().to_canonical() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}
