//! Introductions: agents register and wait, viewers ask for a device by ID,
//! and the server puts them in touch. See `nearhand_core::rendezvous` for the
//! message flow.
//!
//! The registry is in memory. A device's ID comes from its key, so nothing
//! about it needs to outlive the process: an agent that reconnects after a
//! restart registers under the same ID again. Accounts, groups and grants —
//! state worth keeping — arrive with SQLite in M5.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nearhand_core::rendezvous::{DeviceId, FromServer, Refusal, ToServer};
use nearhand_transport::{Fingerprint, peer_fingerprint, recv_message, send_message};
use quinn::{Connection, Endpoint, SendStream};
use tokio::sync::{mpsc, oneshot};

/// How long a client has to say what it wants.
const FIRST_MESSAGE: Duration = Duration::from_secs(10);
/// How long a viewer waits for the agent to open its way.
const AGENT_ANSWER: Duration = Duration::from_secs(10);
/// Addresses taken from any one client. A few interfaces' worth; more would
/// let a client aim the other side's connection attempts at a list of
/// strangers.
const MAX_ADDRESSES: usize = 8;
/// Connection attempts a viewer's address may make per window.
const ATTEMPTS: usize = 10;
const ATTEMPT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct Registry {
    agents: Mutex<HashMap<DeviceId, Agent>>,
    attempts: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    next: AtomicU64,
}

#[derive(Clone)]
struct Agent {
    fingerprint: Fingerprint,
    /// Where the agent says it can be reached on its own network.
    reported: Vec<SocketAddr>,
    /// Its connection here, which tells where it is seen from now: a NAT may
    /// have moved it since it registered.
    conn: Connection,
    to_agent: mpsc::UnboundedSender<FromServer>,
    /// Viewers waiting for this agent to answer, by session.
    waiting: Arc<Mutex<HashMap<u64, oneshot::Sender<bool>>>>,
    /// Which registration this is, so a stale connection going away does not
    /// remove the one that replaced it.
    registration: u64,
}

/// Accept clients until the endpoint closes.
pub async fn serve(endpoint: Endpoint, registry: Arc<Registry>) {
    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::debug!(error = %e, "handshake failed");
                    return;
                }
            };
            let remote = conn.remote_address();
            if let Err(e) = handle(conn, &registry).await {
                tracing::debug!(%remote, error = %format!("{e:#}"), "client ended");
            }
        });
    }
}

async fn handle(conn: Connection, registry: &Registry) -> Result<()> {
    let (mut send, mut recv) = tokio::time::timeout(FIRST_MESSAGE, conn.accept_bi())
        .await
        .context("no stream in time")??;
    let first = tokio::time::timeout(FIRST_MESSAGE, recv_message::<ToServer>(&mut recv))
        .await
        .context("no first message in time")??;
    match first {
        Some(ToServer::Register { addresses }) => {
            let registered = register(&conn, send, registry, addresses).await?;
            // An agent's stream carries its answers until it goes away.
            let result = serve_agent(&mut recv, &registered).await;
            registry.remove(&registered);
            result
        }
        Some(ToServer::Connect { id, addresses }) => {
            introduce(&conn, &mut send, registry, id, addresses).await
        }
        _ => refuse(&conn, &mut send, Refusal::Protocol).await,
    }
}

struct Registered {
    id: DeviceId,
    registration: u64,
    waiting: Arc<Mutex<HashMap<u64, oneshot::Sender<bool>>>>,
}

async fn register(
    conn: &Connection,
    mut send: SendStream,
    registry: &Registry,
    addresses: Vec<SocketAddr>,
) -> Result<Registered> {
    let Some(fingerprint) = peer_fingerprint(conn) else {
        refuse(conn, &mut send, Refusal::NoCertificate).await?;
        bail!("agent without a certificate");
    };
    let id = fingerprint.device_id();
    let observed = conn.remote_address();
    let (to_agent, mut from_server) = mpsc::unbounded_channel();
    let waiting = Arc::new(Mutex::new(HashMap::new()));
    let registration = registry.next.fetch_add(1, Ordering::Relaxed);
    let agent = Agent {
        fingerprint,
        reported: addresses,
        conn: conn.clone(),
        to_agent,
        waiting: waiting.clone(),
        registration,
    };
    let taken = {
        let mut agents = lock(&registry.agents);
        let taken = agents
            .get(&id)
            .is_some_and(|a| a.fingerprint != fingerprint);
        if !taken {
            // The same device again — a reconnect — replaces its old entry.
            agents.insert(id, agent);
        }
        taken
    };
    if taken {
        refuse(conn, &mut send, Refusal::IdTaken).await?;
        bail!("ID {id} is held by another key");
    }
    tracing::info!(%id, %observed, "agent registered");
    send_message(&mut send, &FromServer::Registered { id, observed }).await?;

    // Messages for the agent go out on a task of their own, so a slow agent
    // never holds up the viewers being introduced to it.
    tokio::spawn(async move {
        while let Some(message) = from_server.recv().await {
            if send_message(&mut send, &message).await.is_err() {
                break;
            }
        }
    });
    Ok(Registered {
        id,
        registration,
        waiting,
    })
}

async fn serve_agent(recv: &mut quinn::RecvStream, registered: &Registered) -> Result<()> {
    while let Some(message) = recv_message::<ToServer>(recv).await? {
        let (session, ready) = match message {
            ToServer::Ready { session } => (session, true),
            ToServer::Decline { session } => (session, false),
            other => bail!("unexpected from an agent: {other:?}"),
        };
        if let Some(viewer) = lock(&registered.waiting).remove(&session) {
            let _ = viewer.send(ready);
        }
    }
    Ok(())
}

async fn introduce(
    conn: &Connection,
    send: &mut SendStream,
    registry: &Registry,
    id: DeviceId,
    addresses: Vec<SocketAddr>,
) -> Result<()> {
    let observed = conn.remote_address();
    if !registry.attempt(observed.ip()) {
        return refuse(conn, send, Refusal::TooManyAttempts).await;
    }
    let Some(agent) = lock(&registry.agents).get(&id).cloned() else {
        return refuse(conn, send, Refusal::Offline).await;
    };

    let session = registry.next.fetch_add(1, Ordering::Relaxed);
    let (answer, answered) = oneshot::channel();
    lock(&agent.waiting).insert(session, answer);
    let asked = agent.to_agent.send(FromServer::Incoming {
        session,
        addresses: candidates(addresses, observed),
    });
    let ready = asked.is_ok()
        && matches!(
            tokio::time::timeout(AGENT_ANSWER, answered).await,
            Ok(Ok(true))
        );
    lock(&agent.waiting).remove(&session);
    if !ready {
        return refuse(conn, send, Refusal::Declined).await;
    }

    tracing::info!(%id, viewer = %observed, "introduced");
    let peer = FromServer::Peer {
        fingerprint: *agent.fingerprint.as_bytes(),
        addresses: candidates(agent.reported, agent.conn.remote_address()),
    };
    send_message(send, &peer).await?;
    goodbye(conn, send).await;
    Ok(())
}

async fn refuse(conn: &Connection, send: &mut SendStream, refusal: Refusal) -> Result<()> {
    tracing::debug!(remote = %conn.remote_address(), ?refusal, "refused");
    send_message(send, &FromServer::Refused(refusal)).await?;
    goodbye(conn, send).await;
    Ok(())
}

/// Let the client read the last message before the connection goes: closing
/// at once would discard anything still unsent. The client closes once it has
/// read it; a client that does not is cut off shortly after.
async fn goodbye(conn: &Connection, send: &mut SendStream) {
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
}

impl Registry {
    fn remove(&self, registered: &Registered) {
        let mut agents = lock(&self.agents);
        if agents
            .get(&registered.id)
            .is_some_and(|a| a.registration == registered.registration)
        {
            agents.remove(&registered.id);
            tracing::info!(id = %registered.id, "agent left");
        }
    }

    /// Count an attempt from `ip`; false if it has made too many lately.
    fn attempt(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut attempts = lock(&self.attempts);
        // Forget addresses that have gone quiet, so the table cannot grow
        // without bound.
        attempts.retain(|_, times| {
            times
                .back()
                .is_some_and(|t| now.duration_since(*t) < ATTEMPT_WINDOW)
        });
        let times = attempts.entry(ip).or_default();
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) >= ATTEMPT_WINDOW)
        {
            times.pop_front();
        }
        if times.len() >= ATTEMPTS {
            return false;
        }
        times.push_back(now);
        true
    }

    #[cfg(test)]
    fn online(&self) -> usize {
        lock(&self.agents).len()
    }
}

/// What a client says about where it can be reached, plus where the server
/// sees it, with nonsense and repeats removed.
fn candidates(reported: Vec<SocketAddr>, observed: SocketAddr) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for address in reported
        .into_iter()
        .take(MAX_ADDRESSES)
        .chain(std::iter::once(observed))
    {
        if !address.ip().is_unspecified() && address.port() != 0 && !out.contains(&address) {
            out.push(address);
        }
    }
    out
}

/// A poisoned lock means a thread panicked mid-update; the maps are still
/// usable, and refusing all service over it would be worse.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_drop_nonsense_and_repeats_and_add_the_observed() {
        let lan: SocketAddr = "192.168.1.20:5000".parse().expect("addr");
        let observed: SocketAddr = "203.0.113.7:6000".parse().expect("addr");
        let junk: SocketAddr = "0.0.0.0:5000".parse().expect("addr");
        let no_port: SocketAddr = "192.168.1.21:0".parse().expect("addr");
        assert_eq!(
            candidates(vec![lan, junk, lan, no_port], observed),
            [lan, observed]
        );
        let many: Vec<SocketAddr> = (1..=20)
            .map(|i| SocketAddr::from(([10, 0, 0, i], 5000)))
            .collect();
        assert_eq!(candidates(many, observed).len(), MAX_ADDRESSES + 1);
    }

    #[test]
    fn attempts_are_limited_per_address() {
        let registry = Registry::default();
        let a: IpAddr = "198.51.100.1".parse().expect("ip");
        let b: IpAddr = "198.51.100.2".parse().expect("ip");
        for _ in 0..ATTEMPTS {
            assert!(registry.attempt(a));
        }
        assert!(!registry.attempt(a));
        assert!(registry.attempt(b), "others are unaffected");
        assert_eq!(registry.online(), 0);
    }

    // --- Whole introductions, across simulated NATs -------------------------

    use crate::netsim::{NatKind, Net, private, public};
    use nearhand_transport::rendezvous::{find, stay_registered};
    use nearhand_transport::{Error, Identity, peer_server_config, rendezvous_server_config};
    use quinn::{EndpointConfig, ServerConfig, TokioRuntime};

    #[derive(Debug, Clone, Copy)]
    enum Place {
        Internet,
        Behind(NatKind),
        /// On the agent's private network, behind the same NAT.
        BesideAgent,
    }

    fn endpoint(
        net: &Arc<Net>,
        address: SocketAddr,
        behind: Option<IpAddr>,
        config: Option<ServerConfig>,
    ) -> Endpoint {
        Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            config,
            net.socket(address, behind),
            Arc::new(TokioRuntime),
        )
        .expect("endpoint")
    }

    /// Where a host at `place` lives: its own address, and the NAT it is
    /// behind, set up here. Host `own` gets network and public IP `own`.
    fn place(net: &Net, place: Place, own: u8) -> (SocketAddr, Option<IpAddr>) {
        match place {
            Place::Internet => (public(own, 5000), None),
            Place::Behind(kind) => {
                let nat = public(own, 0).ip();
                net.add_nat(nat, kind);
                (private(own, 2, 5000), Some(nat))
            }
            Place::BesideAgent => (private(AGENT, 3, 5000), Some(public(AGENT, 0).ip())),
        }
    }

    const AGENT: u8 = 1;
    const VIEWER: u8 = 2;

    /// A server on the internet, an agent at `agent`, and a viewer at
    /// `viewer` trying to reach it: where the viewer's connection landed.
    /// `punch: false` has the agent skip opening its way.
    async fn introduce_across(
        agent: Place,
        viewer: Place,
        punch: bool,
    ) -> nearhand_transport::Result<SocketAddr> {
        let world = World::new(agent, punch).await;
        world.reach(viewer).await
    }

    /// A server, and an agent registered with it.
    struct World {
        net: Arc<Net>,
        server_addr: SocketAddr,
        server_fp: Fingerprint,
        registry: Arc<Registry>,
        id: DeviceId,
    }

    impl World {
        async fn new(agent: Place, punch: bool) -> Self {
            let net = Net::new();
            let server_identity = Identity::generate().expect("identity");
            let server_addr = public(100, 443);
            let server = endpoint(
                &net,
                server_addr,
                None,
                Some(rendezvous_server_config(&server_identity).expect("config")),
            );
            let registry = Arc::new(Registry::default());
            tokio::spawn(serve(server, registry.clone()));
            let server_fp = server_identity.fingerprint();

            let (agent_addr, agent_behind) = place(&net, agent, AGENT);
            let agent_identity = Identity::generate().expect("identity");
            let id = agent_identity.device_id();
            let agent = endpoint(
                &net,
                agent_addr,
                agent_behind,
                Some(peer_server_config(&agent_identity).expect("config")),
            );
            let accepting = agent.clone();
            tokio::spawn(async move {
                while let Some(incoming) = accepting.accept().await {
                    tokio::spawn(async move {
                        if let Ok(conn) = incoming.await {
                            conn.closed().await;
                        }
                    });
                }
            });
            if punch {
                tokio::spawn(async move {
                    stay_registered(&agent, server_addr, server_fp, &agent_identity).await
                });
            } else {
                tokio::spawn(register_without_punching(
                    agent,
                    server_addr,
                    server_fp,
                    agent_identity,
                ));
            }
            tokio::time::timeout(Duration::from_secs(5), async {
                while registry.online() == 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("the agent registers");

            Self {
                net,
                server_addr,
                server_fp,
                registry,
                id,
            }
        }

        async fn reach(&self, viewer: Place) -> nearhand_transport::Result<SocketAddr> {
            let (viewer_addr, viewer_behind) = place(&self.net, viewer, VIEWER);
            let viewer = endpoint(&self.net, viewer_addr, viewer_behind, None);
            let conn = find(&viewer, self.server_addr, self.server_fp, self.id).await?;
            Ok(conn.remote_address())
        }

        /// Where the server sees the agent now.
        fn agent_seen_at(&self) -> SocketAddr {
            lock(&self.registry.agents)[&self.id].conn.remote_address()
        }
    }

    /// An agent that says it is ready without sending anything to the viewer.
    async fn register_without_punching(
        endpoint: Endpoint,
        server: SocketAddr,
        server_fp: Fingerprint,
        identity: Identity,
    ) -> Result<()> {
        let conn =
            nearhand_transport::connect_server(&endpoint, server, server_fp, Some(&identity))
                .await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send_message(&mut send, &ToServer::Register { addresses: vec![] }).await?;
        while let Some(message) = recv_message::<FromServer>(&mut recv).await? {
            if let FromServer::Incoming { session, .. } = message {
                send_message(&mut send, &ToServer::Ready { session }).await?;
            }
        }
        Ok(())
    }

    /// The table in docs/protocol.md ("Through NATs"), row by row.
    #[tokio::test]
    async fn which_nats_a_direct_connection_gets_through() {
        use NatKind::*;
        use Place::*;
        let agent_public = public(AGENT, 0).ip();
        let agent_private = private(AGENT, 2, 0).ip();
        let cases = [
            (Internet, Internet, Some(public(AGENT, 0).ip())),
            (Behind(PortRestricted), Internet, Some(agent_public)),
            (
                Behind(PortRestricted),
                Behind(PortRestricted),
                Some(agent_public),
            ),
            (
                Behind(FullCone),
                Behind(AddressRestricted),
                Some(agent_public),
            ),
            (Behind(PortRestricted), Behind(Symmetric), None),
            (
                Behind(AddressRestricted),
                Behind(Symmetric),
                Some(agent_public),
            ),
            (Behind(FullCone), Behind(Symmetric), Some(agent_public)),
            (Behind(Symmetric), Internet, None),
            (Behind(Symmetric), Behind(PortRestricted), None),
            // Same network, and the NAT does not hairpin: the local address.
            (Behind(PortRestricted), BesideAgent, Some(agent_private)),
            (Behind(Symmetric), BesideAgent, Some(agent_private)),
        ];
        let mut runs = tokio::task::JoinSet::new();
        for (i, (agent, viewer, expected)) in cases.into_iter().enumerate() {
            runs.spawn(async move {
                let result = introduce_across(agent, viewer, true).await;
                (i, agent, viewer, expected, result)
            });
        }
        let mut wrong = Vec::new();
        while let Some(run) = runs.join_next().await {
            let (i, agent, viewer, expected, result) = run.expect("case");
            let landed = match &result {
                Ok(address) => Some(address.ip()),
                Err(Error::Unreachable(_)) => None,
                Err(e) => panic!("case {i}: failed before connecting: {e}"),
            };
            if landed != expected {
                wrong.push(format!(
                    "case {i}: agent {agent:?}, viewer {viewer:?}: expected {expected:?}, got {result:?}"
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// Routers drop idle mappings and restart, and the agent's next packet
    /// leaves from a new port. The server follows it, and sends viewers there
    /// rather than to where it registered.
    #[tokio::test]
    async fn an_agent_moved_by_its_nat_is_found_where_it_is_now() {
        let world = World::new(Place::Behind(NatKind::PortRestricted), true).await;
        let before = world.agent_seen_at();
        world.net.forget_mappings(public(AGENT, 0).ip());
        // The agent's keep-alive, every few seconds, leaves from the new port.
        let after = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let now = world.agent_seen_at();
                if now != before {
                    return now;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the server sees the agent move");
        let landed = world.reach(Place::Internet).await.expect("reached");
        assert_eq!(landed, after);
    }

    #[tokio::test]
    async fn without_the_agents_punch_its_nat_keeps_the_viewer_out() {
        let agent = Place::Behind(NatKind::PortRestricted);
        let result = introduce_across(agent, Place::Internet, false).await;
        assert!(matches!(result, Err(Error::Unreachable(_))), "{result:?}");
    }
}
