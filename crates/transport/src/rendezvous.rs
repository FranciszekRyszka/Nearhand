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
//! table in `docs/protocol.md`, and a test in the server crate.
//!
//! ## The relay
//!
//! Alongside the direct attempts the viewer connects through the server's
//! relay ([`crate::relay`]), which gets through anything that lets the two
//! reach the server. A direct connection is preferred — it is faster, and
//! costs the server nothing — so the relayed one is taken only if no direct
//! one is made within [`DIRECT_GRACE`], or every direct attempt has failed.
//! Either way the session is end-to-end encrypted to the agent's pinned key.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

use nearhand_core::ALPN;
use nearhand_core::grant::SignedGrant;
use nearhand_core::proto::close;
use nearhand_core::release::{SignedRelease, Version};
use nearhand_core::rendezvous::{DeviceId, Enrollment, FromServer, ToServer};
use quinn::{Connection, Endpoint};

use crate::relay::{self, is_relayed, relayed_address};
use crate::{
    Error, Fingerprint, Identity, Link, Result, SERVER_NAME, client_config, connect,
    connect_server, peer_server_config, recv_message, send_message,
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
/// How long a direct connection gets to beat a relayed one that is ready.
/// A direct handshake takes a round trip or two once the viewer knows where
/// to go, so a second is ample, and is also the most connecting should take
/// when there is no direct path.
pub const DIRECT_GRACE: Duration = Duration::from_secs(1);

/// Keep this agent registered with the server, reconnecting whenever the
/// connection is lost, and open the way to every viewer the server
/// introduces. Never returns; drop it to stop.
///
/// `endpoint` must be the one that accepts viewers: its socket is the one the
/// server sees, and so the one viewers are sent to. `events` hears how the
/// registration is going — including, each time it is made, the endpoint
/// viewers who come through the relay arrive on, to accept them from. That
/// endpoint closes when its server connection is lost.
pub async fn stay_registered(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
    events: impl Fn(Registration),
) {
    let mut wait = RECONNECT_FIRST;
    loop {
        match register(endpoint, server, server_fingerprint, identity, &events).await {
            // Registered for a while and then lost: reconnect promptly.
            Ok(()) => {
                tracing::info!("server connection ended; reconnecting");
                wait = RECONNECT_FIRST;
                events(Registration::Lost {
                    error: "the connection to the server ended".into(),
                    retry_in: wait,
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, retry_in = ?wait, "server unreachable");
                events(Registration::Lost {
                    error: e.to_string(),
                    retry_in: wait,
                });
            }
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(RECONNECT_MAX);
    }
}

/// How an agent's registration with its server is going.
pub enum Registration {
    /// Registered: viewers can find this device. Relayed ones arrive on
    /// `relay`.
    Registered { relay: Endpoint },
    /// Not registered, and trying again in `retry_in`.
    Lost { error: String, retry_in: Duration },
}

async fn register(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
    events: &impl Fn(Registration),
) -> Result<()> {
    let conn = connect_server(endpoint, server, server_fingerprint, Some(identity)).await?;
    let relay = relay::endpoint(conn.clone(), true, Some(peer_server_config(identity)?))?;
    let result = serve_registration(endpoint, &conn, relay.clone(), events).await;
    relay.close(close::NORMAL.into(), b"server connection lost");
    result
}

async fn serve_registration(
    endpoint: &Endpoint,
    conn: &Connection,
    relay: Endpoint,
    events: &impl Fn(Registration),
) -> Result<()> {
    let server = conn.remote_address();
    let (mut send, mut recv) = conn.open_bi().await?;
    let addresses = own_addresses(endpoint, server);
    send_message(&mut send, &ToServer::Register { addresses }).await?;
    match recv_message::<FromServer>(&mut recv).await? {
        Some(FromServer::Registered { id, observed }) => {
            tracing::info!(%id, %observed, "registered with the server");
            events(Registration::Registered { relay });
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

/// Enroll this agent with the server's managed devices, once, with a token
/// an administrator made. The server learns the device's key from the
/// certificate it connects with, as when registering.
pub async fn enroll(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
    enrollment: Enrollment,
) -> Result<DeviceId> {
    let conn = connect_server(endpoint, server, server_fingerprint, Some(identity)).await?;
    let answer = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        send_message(&mut send, &ToServer::Enroll(enrollment)).await?;
        match recv_message::<FromServer>(&mut recv).await? {
            Some(FromServer::Enrolled { id }) => Ok(id),
            Some(FromServer::Refused(refusal)) => Err(Error::Refused(refusal)),
            other => Err(Error::Unexpected(format!("{other:?}"))),
        }
    }
    .await;
    conn.close(close::NORMAL.into(), b"enrolled");
    answer
}

/// A release the server offers this agent, not yet fetched: its connection
/// stays open until [`Offered::fetch`], or until this is dropped.
pub struct Offered {
    /// Unchecked: the caller verifies it before fetching, and the package
    /// after.
    pub signed: SignedRelease,
    conn: Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl Offered {
    /// The package, at most `size` bytes: the size the verified release
    /// gives. A server sending more is cut off.
    pub async fn fetch(mut self, size: u64) -> Result<Vec<u8>> {
        send_message(&mut self.send, &ToServer::Fetch).await?;
        let limit = usize::try_from(size).unwrap_or(usize::MAX);
        let package = self
            .recv
            .read_to_end(limit)
            .await
            .map_err(|e| Error::Unexpected(format!("fetching the package: {e}")))?;
        self.conn.close(close::NORMAL.into(), b"fetched");
        Ok(package)
    }
}

impl Drop for Offered {
    fn drop(&mut self) {
        self.conn.close(close::NORMAL.into(), b"done");
    }
}

/// Ask the server whether there is a release of `product` for `platform`
/// newer than `version`, as the agent with `identity`.
pub async fn check_update(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
    product: &str,
    platform: &str,
    version: Version,
) -> Result<Option<Offered>> {
    let conn = connect_server(endpoint, server, server_fingerprint, Some(identity)).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let asked = ToServer::Update {
        product: product.to_owned(),
        platform: platform.to_owned(),
        version,
    };
    let answer = async {
        send_message(&mut send, &asked).await?;
        recv_message::<FromServer>(&mut recv).await
    }
    .await;
    match answer {
        Ok(Some(FromServer::Offered(Some(signed)))) => Ok(Some(Offered {
            signed,
            conn,
            send,
            recv,
        })),
        other => {
            conn.close(close::NORMAL.into(), b"done");
            match other? {
                Some(FromServer::Offered(None)) => Ok(None),
                Some(FromServer::Refused(refusal)) => Err(Error::Refused(refusal)),
                other => Err(Error::Unexpected(format!("{other:?}"))),
            }
        }
    }
}

/// Ask the server to introduce this viewer to device `id`, then connect to it
/// — directly if that works, through the server's relay if not — pinned to
/// the key the server reports for it. [`path_of`] the connection's remote
/// address says which way it went.
///
/// Everything goes out from `endpoint`'s one socket: the address the server
/// sees is the one the agent opens its way to.
pub async fn find(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    id: DeviceId,
    route: Route,
) -> Result<Connection> {
    let (conn, _) = introduce(endpoint, server, server_fingerprint, id, route, None).await?;
    Ok(conn)
}

/// [`find`], as the user whose API token `token` is: the server hands back a
/// grant for the device, to present to it, if the user has one.
pub async fn find_granted(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    id: DeviceId,
    route: Route,
    token: &str,
) -> Result<(Connection, SignedGrant)> {
    let (conn, grant) =
        introduce(endpoint, server, server_fingerprint, id, route, Some(token)).await?;
    match grant {
        Some(grant) => Ok((conn, grant)),
        None => Err(Error::Unexpected("the server sent no grant".into())),
    }
}

async fn introduce(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    id: DeviceId,
    route: Route,
    token: Option<&str>,
) -> Result<(Connection, Option<SignedGrant>)> {
    let introducer = connect_server(endpoint, server, server_fingerprint, None).await?;
    let (mut send, mut recv) = introducer.open_bi().await?;
    let addresses = own_addresses(endpoint, server);
    let request = match token {
        Some(token) => ToServer::ConnectAs {
            id,
            addresses,
            token: token.to_owned(),
        },
        None => ToServer::Connect { id, addresses },
    };
    send_message(&mut send, &request).await?;
    let mut answer = recv_message::<FromServer>(&mut recv).await?;
    let mut grant = None;
    if let Some(FromServer::Granted(granted)) = answer {
        grant = Some(granted);
        answer = recv_message::<FromServer>(&mut recv).await?;
    }
    let (fingerprint, addresses) = match answer {
        Some(FromServer::Peer {
            fingerprint,
            addresses,
        }) => (Fingerprint::from_bytes(fingerprint), addresses),
        Some(FromServer::Refused(refusal)) => {
            introducer.close(close::NORMAL.into(), b"refused");
            return Err(Error::Refused(refusal));
        }
        other => {
            introducer.close(close::NORMAL.into(), b"unexpected");
            return Err(Error::Unexpected(format!("{other:?}")));
        }
    };
    // Not a security check — ten digits are easily matched on purpose — but
    // it catches a server that mixes up its devices.
    if fingerprint.device_id() != id {
        introducer.close(close::NORMAL.into(), b"wrong key");
        return Err(Error::Unexpected(
            "the server answered with another device's key".into(),
        ));
    }
    tracing::info!(?addresses, "introduced; connecting");

    // The introduction's connection is the relay's tunnel, so it stays open
    // for as long as a relayed session might need it.
    let tunnel = relay::endpoint(introducer.clone(), false, None)?;
    let direct = async {
        match route {
            Route::Best => race(endpoint, &addresses, fingerprint).await,
            Route::RelayOnly => Err(Error::Unreachable("direct not tried".into())),
        }
    };
    let through_relay = async {
        tokio::time::timeout(
            PEER_CONNECT_TIMEOUT,
            connect(&tunnel, relayed_address(0), fingerprint),
        )
        .await
        .unwrap_or_else(|_| Err(Error::Unreachable("no answer through the relay".into())))
    };
    let conn = match prefer_direct(direct, through_relay, DIRECT_GRACE).await {
        Ok(conn) if is_relayed(conn.remote_address()) => {
            // Done with the tunnel once the session is: after its last
            // packets have left, close what carries them.
            let session = conn.clone();
            tokio::spawn(async move {
                session.closed().await;
                tunnel.wait_idle().await;
                introducer.close(close::NORMAL.into(), b"session over");
            });
            conn
        }
        result => {
            introducer.close(close::NORMAL.into(), b"introduced");
            result?
        }
    };
    Ok((conn, grant))
}

/// The direct connection if it is made within `grace` of the relayed one
/// being ready (or at all, while the relay is not), else the relayed one.
async fn prefer_direct(
    direct: impl Future<Output = Result<Connection>>,
    relayed: impl Future<Output = Result<Connection>>,
    grace: Duration,
) -> Result<Connection> {
    tokio::pin!(direct, relayed);
    let deadline = tokio::time::sleep(Duration::MAX);
    tokio::pin!(deadline);
    let mut direct_failed = None;
    let mut relay_failed = None;
    let mut ready: Option<Connection> = None;
    loop {
        tokio::select! {
            result = &mut direct, if direct_failed.is_none() => match result {
                Ok(conn) => {
                    if let Some(relayed) = ready {
                        relayed.close(close::NORMAL.into(), b"direct connection made");
                    }
                    return Ok(conn);
                }
                Err(e) => match ready {
                    Some(relayed) => return Ok(relayed),
                    None => direct_failed = Some(e),
                },
            },
            result = &mut relayed, if ready.is_none() && relay_failed.is_none() => match result {
                Ok(conn) if direct_failed.is_some() => return Ok(conn),
                Ok(conn) => {
                    ready = Some(conn);
                    deadline
                        .as_mut()
                        .reset(tokio::time::Instant::now() + grace);
                }
                Err(e) => relay_failed = Some(e),
            },
            () = &mut deadline, if ready.is_some() => {
                return ready.ok_or_else(|| Error::Unreachable("relay vanished".into()));
            }
        }
        if let (Some(direct), Some(relay)) = (&direct_failed, &relay_failed) {
            return Err(Error::Unreachable(format!("{direct}; relay: {relay}")));
        }
    }
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
    Err(Error::Unreachable(format!(
        "direct: {}",
        failures.join("; ")
    )))
}

/// Open this endpoint's way to `target` through the local firewall and NAT,
/// by sending it a packet.
///
/// The packet is the first of a connection attempt that will never complete:
/// what matters is that it left. The attempt is kept alive for `hold`, so QUIC
/// resends it in the meantime.
async fn punch(endpoint: &Endpoint, target: SocketAddr, hold: Duration) {
    let Ok(config) = client_config(Fingerprint::from_bytes([0; 32]), ALPN, None, Link::Peer) else {
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

/// Which ways [`find`] may try.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Route {
    /// Direct if possible, else relayed.
    #[default]
    Best,
    /// Relayed only: for testing the relay, and measuring what it costs.
    RelayOnly,
}

/// Which way a connection to `remote` went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    /// Direct, within a private network.
    Local,
    /// Direct, across the internet.
    Internet,
    /// Through the server's relay.
    Relayed,
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Path::Local => "on the local network",
            Path::Internet => "across the internet",
            Path::Relayed => "through the server's relay",
        })
    }
}

pub fn path_of(remote: SocketAddr) -> Path {
    if is_relayed(remote) {
        Path::Relayed
    } else if is_local(remote) {
        Path::Local
    } else {
        Path::Internet
    }
}

/// Whether `address` belongs to a private network: a connection to it did
/// not cross the internet.
fn is_local(address: SocketAddr) -> bool {
    match address.ip().to_canonical() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}
