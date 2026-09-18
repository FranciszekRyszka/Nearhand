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
    addresses: Vec<SocketAddr>,
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
        addresses: candidates(addresses, observed),
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
        addresses: agent.addresses.clone(),
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
}
