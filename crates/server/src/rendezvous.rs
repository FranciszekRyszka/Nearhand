//! Introductions: agents register and wait, viewers ask for a device by ID,
//! and the server puts them in touch. See `nearhand_core::rendezvous` for the
//! message flow.
//!
//! Introduced, the viewer's connection stays open as the relay's tunnel: the
//! server forwards datagrams between it and the agent's connection, tagging
//! them with the session on the agent's side (`nearhand_transport::relay`).
//! The session inside is end-to-end encrypted to the agent's key, so the
//! server passes on packets it cannot read. Only the two connections it paired
//! can use a tunnel, and only once the agent has said it is ready: the relay
//! is no open proxy.
//!
//! The registry is in memory. A device's ID comes from its key, so nothing
//! about it needs to outlive the process: an agent that reconnects after a
//! restart registers under the same ID again. What is kept is about managed
//! devices (`devices`): the registry enrolls agents that bring a token, and
//! notes when an enrolled one comes and goes.
//!
//! An enrolled device also outranks a stranger for its ID. Ten digits are
//! easily matched on purpose, so someone could register a key with a managed
//! device's ID first, to keep the device from being found; the device, when
//! it comes, takes the ID over.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nearhand_core::rendezvous::{DeviceId, Enrollment, FromServer, Refusal, ToServer};
use nearhand_transport::relay::{tag, untag};
use nearhand_transport::{Fingerprint, peer_fingerprint, recv_message, send_message};
use quinn::{Connection, Endpoint, SendStream};
use tokio::sync::{mpsc, oneshot};

use crate::devices::Devices;

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

type Relays = Arc<Mutex<HashMap<u64, Relay>>>;

struct Relay {
    viewer: Connection,
    /// Bytes relayed to the viewer.
    to_viewer: Arc<AtomicU64>,
}

#[derive(Default)]
pub struct Registry {
    agents: Mutex<HashMap<DeviceId, Agent>>,
    attempts: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    next: AtomicU64,
    /// The managed devices; without them, agents can only register.
    devices: Option<Arc<Devices>>,
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
    /// Viewers' connections, by session, for relaying the agent's datagrams.
    relays: Relays,
    /// Which registration this is, so a stale connection going away does not
    /// remove the one that replaced it.
    registration: u64,
    /// Whether it is a managed device, which may take its ID from a stranger.
    enrolled: bool,
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
            registry.remove(&registered, &conn).await;
            result
        }
        Some(ToServer::Connect { id, addresses }) => {
            introduce(&conn, &mut send, registry, id, addresses).await
        }
        Some(ToServer::Enroll(enrollment)) => enroll(&conn, &mut send, registry, enrollment).await,
        _ => refuse(&conn, &mut send, Refusal::Protocol).await,
    }
}

struct Registered {
    id: DeviceId,
    fingerprint: Fingerprint,
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
    let enrolled = registry.is_enrolled(&fingerprint).await;
    let (to_agent, mut from_server) = mpsc::unbounded_channel();
    let waiting = Arc::new(Mutex::new(HashMap::new()));
    let relays = Relays::default();
    let registration = registry.next.fetch_add(1, Ordering::Relaxed);
    let agent = Agent {
        fingerprint,
        reported: addresses,
        conn: conn.clone(),
        to_agent,
        waiting: waiting.clone(),
        relays: relays.clone(),
        registration,
        enrolled,
    };
    let (taken, displaced) = {
        let mut agents = lock(&registry.agents);
        let holder = agents.get(&id);
        match claim(
            holder.map(|a| (&a.fingerprint, a.enrolled)),
            &fingerprint,
            enrolled,
        ) {
            Claim::Refuse => (true, None),
            claim => {
                let displaced = (claim == Claim::Displace)
                    .then(|| holder.map(|a| a.conn.clone()))
                    .flatten();
                agents.insert(id, agent);
                (false, displaced)
            }
        }
    };
    if taken {
        refuse(conn, &mut send, Refusal::IdTaken).await?;
        bail!("ID {id} is held by another key");
    }
    if let Some(stranger) = displaced {
        tracing::warn!(
            %id,
            stranger = %stranger.remote_address(),
            "another key held a managed device's ID; the device takes it over"
        );
        stranger.close(0u32.into(), b"ID taken over by its managed device");
    }
    tracing::info!(%id, %observed, enrolled, "agent registered");
    registry.seen(&fingerprint, observed).await;
    send_message(&mut send, &FromServer::Registered { id, observed }).await?;

    // The agent's relayed packets, each to its session's viewer. Ends when
    // the agent's connection does.
    let from_agent = conn.clone();
    tokio::spawn(async move {
        while let Ok(datagram) = from_agent.read_datagram().await {
            let Some((session, packet)) = untag(&datagram) else {
                continue;
            };
            let relay = lock(&relays)
                .get(&session)
                .map(|r| (r.viewer.clone(), r.to_viewer.clone()));
            if let Some((viewer, count)) = relay {
                count.fetch_add(packet.len() as u64, Ordering::Relaxed);
                // A full queue drops the oldest datagrams; the connection
                // inside recovers, as from any loss.
                let _ = viewer.send_datagram(packet);
            }
        }
    });

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
        fingerprint,
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
        addresses: candidates(agent.reported.clone(), agent.conn.remote_address()),
    };
    send_message(send, &peer).await?;
    let _ = send.finish();
    relay(conn, &agent, session).await;
    Ok(())
}

/// Forward the viewer's datagrams to the agent, and the agent's for this
/// session back, until the viewer closes its connection: at once when it
/// connected directly, at the end of the session when it did not.
async fn relay(viewer: &Connection, agent: &Agent, session: u64) {
    let to_viewer = Arc::new(AtomicU64::new(0));
    lock(&agent.relays).insert(
        session,
        Relay {
            viewer: viewer.clone(),
            to_viewer: to_viewer.clone(),
        },
    );
    let mut to_agent = 0u64;
    while let Ok(datagram) = viewer.read_datagram().await {
        to_agent += datagram.len() as u64;
        let _ = agent.conn.send_datagram(tag(session, &datagram));
    }
    lock(&agent.relays).remove(&session);
    let to_viewer = to_viewer.load(Ordering::Relaxed);
    if to_agent + to_viewer > 0 {
        tracing::info!(
            session,
            to_agent_kb = to_agent / 1024,
            to_viewer_kb = to_viewer / 1024,
            "relayed session ended"
        );
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Claim {
    /// The ID is free, or held by this same key — a reconnect.
    Take,
    /// A managed device takes its ID from a stranger's key.
    Displace,
    /// Another key holds it, and this one does not outrank it.
    Refuse,
}

/// Whether a key may register under an ID that `holder` — its key, and
/// whether it is enrolled — may hold now.
fn claim(holder: Option<(&Fingerprint, bool)>, key: &Fingerprint, enrolled: bool) -> Claim {
    match holder {
        None => Claim::Take,
        Some((held, _)) if held == key => Claim::Take,
        Some((_, false)) if enrolled => Claim::Displace,
        Some(_) => Claim::Refuse,
    }
}

/// An agent with a token joins the managed devices.
async fn enroll(
    conn: &Connection,
    send: &mut SendStream,
    registry: &Registry,
    enrollment: Enrollment,
) -> Result<()> {
    let Some(fingerprint) = peer_fingerprint(conn) else {
        return refuse(conn, send, Refusal::NoCertificate).await;
    };
    let from = conn.remote_address();
    // Tokens cannot be guessed, but each try costs a database write.
    if !registry.attempt(from.ip()) {
        return refuse(conn, send, Refusal::TooManyAttempts).await;
    }
    let Some(devices) = &registry.devices else {
        return refuse(conn, send, Refusal::Enrollment).await;
    };
    let id = fingerprint.device_id();
    match devices.enroll(&fingerprint, &enrollment, from).await {
        Ok(device) => {
            tracing::info!(%id, name = %device.name, %from, "device enrolled");
            // Registered already, under this key: managed from now on.
            if let Some(agent) = lock(&registry.agents).get_mut(&id)
                && agent.fingerprint == fingerprint
            {
                agent.enrolled = true;
            }
            send_message(send, &FromServer::Enrolled { id }).await?;
            goodbye(conn, send).await;
            Ok(())
        }
        Err(refused) => {
            tracing::info!(%id, %from, error = %refused, "enrollment refused");
            refuse(conn, send, Refusal::Enrollment).await
        }
    }
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
    /// A registry that enrolls devices into `devices`, and keeps their
    /// presence there.
    pub fn new(devices: Arc<Devices>) -> Self {
        Self {
            devices: Some(devices),
            ..Self::default()
        }
    }

    /// Where the device with this key is connected from, if it is.
    pub fn online(&self, fingerprint: &Fingerprint) -> Option<SocketAddr> {
        lock(&self.agents)
            .get(&fingerprint.device_id())
            .filter(|a| a.fingerprint == *fingerprint)
            .map(|a| a.conn.remote_address())
    }

    async fn is_enrolled(&self, fingerprint: &Fingerprint) -> bool {
        let Some(devices) = &self.devices else {
            return false;
        };
        devices.is_enrolled(fingerprint).await.unwrap_or_else(|e| {
            tracing::error!(error = %e, "looking up a device");
            false
        })
    }

    async fn seen(&self, fingerprint: &Fingerprint, from: SocketAddr) {
        if let Some(devices) = &self.devices
            && let Err(e) = devices.seen(fingerprint, from).await
        {
            tracing::error!(error = %e, "noting a device's presence");
        }
    }

    async fn remove(&self, registered: &Registered, conn: &Connection) {
        let removed = {
            let mut agents = lock(&self.agents);
            let current = agents
                .get(&registered.id)
                .is_some_and(|a| a.registration == registered.registration);
            if current {
                agents.remove(&registered.id);
            }
            current
        };
        if removed {
            tracing::info!(id = %registered.id, "agent left");
            // Last seen as it goes.
            self.seen(&registered.fingerprint, conn.remote_address())
                .await;
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
    fn registered(&self) -> usize {
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
    fn a_managed_device_outranks_a_stranger_for_its_id() {
        let device = Fingerprint::from_bytes([1; 32]);
        let stranger = Fingerprint::from_bytes([2; 32]);
        assert_eq!(claim(None, &stranger, false), Claim::Take);
        assert_eq!(claim(Some((&device, true)), &device, true), Claim::Take);
        assert_eq!(
            claim(Some((&device, false)), &stranger, false),
            Claim::Refuse
        );
        assert_eq!(
            claim(Some((&stranger, false)), &device, true),
            Claim::Displace
        );
        assert_eq!(
            claim(Some((&device, true)), &stranger, false),
            Claim::Refuse,
            "a stranger never displaces a managed device"
        );
        assert_eq!(
            claim(Some((&device, true)), &stranger, true),
            Claim::Refuse,
            "nor one managed device another: first come keeps it"
        );
    }

    #[tokio::test]
    async fn agents_enroll_with_a_token_and_are_seen_when_they_register() {
        use crate::accounts::Accounts;
        use nearhand_core::rendezvous::Enrollment;
        use nearhand_transport::rendezvous::enroll;
        use nearhand_transport::{Error, rendezvous_endpoint, server_endpoint};

        let pool = crate::db::in_memory().await;
        let accounts = Accounts::new(pool.clone());
        let setup = accounts.new_setup_token().await.expect("setup token");
        let admin = accounts
            .setup(&setup, "ada", "correct horse battery")
            .await
            .expect("admin");
        let devices = Arc::new(Devices::new(pool));
        let (_, token) = devices
            .new_enroll_token(&admin, "rollout", None, Some(1), 1)
            .await
            .expect("token");

        let server_identity = Identity::generate().expect("server key");
        let server = rendezvous_endpoint(([127, 0, 0, 1], 0).into(), &server_identity)
            .expect("server endpoint");
        let server_addr = server.local_addr().expect("addr");
        let registry = Arc::new(Registry::new(devices.clone()));
        tokio::spawn(serve(server.clone(), registry.clone()));

        let identity = Arc::new(Identity::generate().expect("agent key"));
        let agent = server_endpoint(([127, 0, 0, 1], 0).into(), &identity).expect("agent");
        let asking = |token: &str| Enrollment {
            token: token.into(),
            name: "RECEPTION".into(),
            os: "windows x86_64".into(),
            version: "0.1.0".into(),
        };
        let fp = server_identity.fingerprint();
        let wrong = enroll(&agent, server_addr, fp, &identity, asking("nhe_guess")).await;
        assert!(
            matches!(wrong, Err(Error::Refused(Refusal::Enrollment))),
            "{wrong:?}"
        );
        let id = enroll(&agent, server_addr, fp, &identity, asking(&token))
            .await
            .expect("enrolled");
        assert_eq!(id, identity.device_id());
        let again = enroll(&agent, server_addr, fp, &identity, asking(&token)).await;
        assert!(again.is_err(), "the token was for one device");

        let listed = devices.devices().await.expect("devices");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "RECEPTION");
        assert_eq!(listed[0].fingerprint, identity.fingerprint().to_string());
        assert!(registry.online(&identity.fingerprint()).is_none());

        let registering = {
            let agent = agent.clone();
            let identity = identity.clone();
            tokio::spawn(async move {
                stay_registered(&agent, server_addr, fp, &identity, |_| {}).await
            })
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while registry.online(&identity.fingerprint()).is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the agent registers");
        assert!(lock(&registry.agents)[&id].enrolled);
        registering.abort();
        server.close(0u32.into(), b"done");
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
        assert_eq!(registry.registered(), 0);
    }

    // --- Whole introductions, across simulated NATs -------------------------

    use crate::netsim::{NatKind, Net, private, public};
    use nearhand_transport::rendezvous::{
        DIRECT_GRACE, Path, Registration, Route, find, path_of, stay_registered,
    };
    use nearhand_transport::{Identity, peer_server_config, relay, rendezvous_server_config};
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

    /// Accept viewers on `endpoint`, echoing whatever each sends on its first
    /// stream: enough to show a session's data gets through both ways.
    fn echo(endpoint: Endpoint) {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await
                        && let Ok(data) = recv.read_to_end(64 * 1024).await
                    {
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                    }
                    conn.closed().await;
                });
            }
        });
    }

    /// Where a viewer's connection went, how long connecting took, and the
    /// connection itself.
    struct Reached {
        remote: SocketAddr,
        took: Duration,
        conn: Connection,
    }

    impl Reached {
        /// The agent's IP for a direct connection; `None` when relayed.
        fn direct_to(&self) -> Option<IpAddr> {
            (path_of(self.remote) != Path::Relayed).then_some(self.remote.ip())
        }
    }

    /// A server on the internet and an agent registered with it.
    /// `punch: false` has the agent skip opening its way to viewers.
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
            echo(agent.clone());
            if punch {
                tokio::spawn(async move {
                    let events = |event| {
                        if let Registration::Registered { relay } = event {
                            echo(relay);
                        }
                    };
                    stay_registered(&agent, server_addr, server_fp, &agent_identity, events).await
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
                while registry.registered() == 0 {
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

        async fn reach(&self, viewer: Place) -> nearhand_transport::Result<Reached> {
            let (viewer_addr, viewer_behind) = place(&self.net, viewer, VIEWER);
            let viewer = endpoint(&self.net, viewer_addr, viewer_behind, None);
            let start = std::time::Instant::now();
            let conn = find(
                &viewer,
                self.server_addr,
                self.server_fp,
                self.id,
                Route::Best,
            )
            .await?;
            let took = start.elapsed();

            // More than one packet's worth, so relayed data is split and
            // reassembled like any other.
            let message: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
            let (mut send, mut recv) = conn.open_bi().await.expect("stream");
            send.write_all(&message).await.expect("write");
            send.finish().expect("finish");
            let echoed = recv.read_to_end(64 * 1024).await.expect("echo");
            assert_eq!(echoed, message, "the session's data gets through");
            Ok(Reached {
                remote: conn.remote_address(),
                took,
                conn,
            })
        }

        /// Where the server sees the agent now.
        fn agent_seen_at(&self) -> SocketAddr {
            lock(&self.registry.agents)[&self.id].conn.remote_address()
        }

        fn relayed_sessions(&self) -> usize {
            lock(&lock(&self.registry.agents)[&self.id].relays).len()
        }
    }

    /// An agent that says it is ready without sending anything to the viewer.
    /// It still takes relayed viewers.
    async fn register_without_punching(
        endpoint: Endpoint,
        server: SocketAddr,
        server_fp: Fingerprint,
        identity: Identity,
    ) -> Result<()> {
        let conn =
            nearhand_transport::connect_server(&endpoint, server, server_fp, Some(&identity))
                .await?;
        echo(relay::endpoint(
            conn.clone(),
            true,
            Some(peer_server_config(&identity)?),
        )?);
        let (mut send, mut recv) = conn.open_bi().await?;
        send_message(&mut send, &ToServer::Register { addresses: vec![] }).await?;
        while let Some(message) = recv_message::<FromServer>(&mut recv).await? {
            if let FromServer::Incoming { session, .. } = message {
                send_message(&mut send, &ToServer::Ready { session }).await?;
            }
        }
        Ok(())
    }

    /// The table in docs/protocol.md ("Through NATs"), row by row: a direct
    /// connection wherever there is a path for one, and the relay, within
    /// about a second, wherever there is not.
    #[tokio::test]
    async fn direct_where_the_nats_allow_and_relayed_where_not() {
        use NatKind::*;
        use Place::*;
        let agent_public = Some(public(AGENT, 0).ip());
        let agent_private = Some(private(AGENT, 2, 0).ip());
        let relayed = None;
        let cases = [
            (Internet, Internet, agent_public),
            (Behind(PortRestricted), Internet, agent_public),
            (Behind(PortRestricted), Behind(PortRestricted), agent_public),
            (Behind(FullCone), Behind(AddressRestricted), agent_public),
            (Behind(PortRestricted), Behind(Symmetric), relayed),
            (Behind(AddressRestricted), Behind(Symmetric), agent_public),
            (Behind(FullCone), Behind(Symmetric), agent_public),
            (Behind(Symmetric), Internet, relayed),
            (Behind(Symmetric), Behind(PortRestricted), relayed),
            (Behind(Symmetric), Behind(Symmetric), relayed),
            // Same network, and the NAT does not hairpin: the local address.
            (Behind(PortRestricted), BesideAgent, agent_private),
            (Behind(Symmetric), BesideAgent, agent_private),
        ];
        let mut runs = tokio::task::JoinSet::new();
        for (i, (agent, viewer, expected)) in cases.into_iter().enumerate() {
            runs.spawn(async move {
                let world = World::new(agent, true).await;
                let result = world.reach(viewer).await;
                (i, agent, viewer, expected, result)
            });
        }
        let mut wrong = Vec::new();
        while let Some(run) = runs.join_next().await {
            let (i, agent, viewer, expected, result) = run.expect("case");
            let case = format!("case {i}: agent {agent:?}, viewer {viewer:?}");
            let reached = match result {
                Ok(reached) => reached,
                Err(e) => {
                    wrong.push(format!("{case}: not reached: {e}"));
                    continue;
                }
            };
            if reached.direct_to() != expected {
                wrong.push(format!(
                    "{case}: expected {expected:?}, went {} to {}",
                    path_of(reached.remote),
                    reached.remote
                ));
            }
            if reached.took > DIRECT_GRACE + Duration::from_millis(1500) {
                wrong.push(format!("{case}: took {:?}", reached.took));
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
        let reached = world.reach(Place::Internet).await.expect("reached");
        assert_eq!(reached.remote, after, "directly, at the new port");
    }

    /// Shows the punch is what opens the agent's NAT: without it, the same
    /// pair that connects directly above has to be relayed.
    #[tokio::test]
    async fn without_the_agents_punch_its_nat_keeps_the_viewer_out() {
        let world = World::new(Place::Behind(NatKind::PortRestricted), false).await;
        let reached = world.reach(Place::Internet).await.expect("reached");
        assert_eq!(path_of(reached.remote), Path::Relayed);
    }

    #[tokio::test]
    async fn the_relay_is_released_when_the_session_ends() {
        let world = World::new(Place::Behind(NatKind::Symmetric), true).await;
        let reached = world.reach(Place::Internet).await.expect("reached");
        assert_eq!(path_of(reached.remote), Path::Relayed);
        assert_eq!(world.relayed_sessions(), 1);

        reached.conn.close(0u32.into(), b"done");
        tokio::time::timeout(Duration::from_secs(10), async {
            while world.relayed_sessions() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the server lets the session go");
    }

    /// A viewer that connects directly closes its introduction, and with it
    /// the tunnel it did not need.
    #[tokio::test]
    async fn a_direct_session_leaves_no_relay_behind() {
        let world = World::new(Place::Behind(NatKind::PortRestricted), true).await;
        let reached = world.reach(Place::Internet).await.expect("reached");
        assert_ne!(path_of(reached.remote), Path::Relayed);
        tokio::time::timeout(Duration::from_secs(5), async {
            while world.relayed_sessions() > 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("no relay held open");
    }
}
