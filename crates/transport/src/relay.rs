//! The relay, from the clients' side: a UDP socket, as far as QUIC can tell,
//! whose packets travel as QUIC datagrams on a connection to the server.
//!
//! Viewer and agent run their usual end-to-end QUIC connection over it, the
//! agent's key pinned as always, so the server forwards packets it cannot
//! read. The connection carrying them is one each side already has: the
//! agent's registration and the viewer's introduction. No other port is
//! needed, and only the two connections the server paired can use it.
//!
//! On the agent's side one tunnel carries every relayed viewer, so its
//! datagrams begin with the session's number, big-endian; the server adds it
//! on the way to the agent and strips it on the way to the viewer, whose
//! tunnel carries one session only. To QUIC, each relayed peer is an address
//! in `100::/64` — a range reserved for discarding traffic, so it can never
//! be a real host — with the session in the low 64 bits.
//!
//! The tunnel's carrier need not be a QUIC connection: anything that sends
//! and receives datagrams will do ([`Carrier`]). A browser's is a
//! WebTransport session.

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::{BufMut, Bytes, BytesMut};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Connection, Endpoint, EndpointConfig, ServerConfig, UdpPoller};

use crate::Result;

/// The first 64 bits of every relayed peer's address: `100::/64`.
const PREFIX: u128 = 0x0100 << 112;
/// Bytes of session number before each datagram on an agent's tunnel.
pub const SESSION_LEN: usize = 8;

/// The address QUIC sees for the peer of relayed `session`.
pub fn relayed_address(session: u64) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(PREFIX | u128::from(session))),
        443,
    )
}

/// Whether `address` is a peer reached through the relay.
pub fn is_relayed(address: SocketAddr) -> bool {
    session_of(address).is_some()
}

fn session_of(address: SocketAddr) -> Option<u64> {
    let IpAddr::V6(ip) = address.ip() else {
        return None;
    };
    let bits = u128::from(ip);
    (bits >> 64 == PREFIX >> 64).then_some(bits as u64)
}

/// A datagram for the agent of `session`: the session, then the packet.
pub fn tag(session: u64, packet: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(SESSION_LEN + packet.len());
    out.put_u64(session);
    out.put_slice(packet);
    out.freeze()
}

/// The session and packet of a datagram from an agent.
pub fn untag(datagram: &Bytes) -> Option<(u64, Bytes)> {
    let head = datagram.get(..SESSION_LEN)?;
    let session = u64::from_be_bytes(head.try_into().ok()?);
    Some((session, datagram.slice(SESSION_LEN..)))
}

/// What a tunnel's packets travel in: a connection that sends and receives
/// datagrams.
pub trait Carrier: Send + Sync + 'static {
    /// Send one datagram; false if it could not go, which is a lost packet.
    fn send_datagram(&self, datagram: Bytes) -> bool;
    /// The next datagram, or none once the carrier has closed.
    fn read_datagram(&self) -> Pin<Box<dyn Future<Output = Option<Bytes>> + Send + '_>>;
    /// For logs.
    fn describe(&self) -> String;
}

impl Carrier for Connection {
    fn send_datagram(&self, datagram: Bytes) -> bool {
        Connection::send_datagram(self, datagram).is_ok()
    }

    fn read_datagram(&self) -> Pin<Box<dyn Future<Output = Option<Bytes>> + Send + '_>> {
        Box::pin(async move { Connection::read_datagram(self).await.ok() })
    }

    fn describe(&self) -> String {
        format!("via {}", self.remote_address())
    }
}

/// An endpoint whose socket is a tunnel over `carrier`, serving `config` if
/// given (the agent's) or connecting only (the viewer's).
///
/// `tagged` is true on the agent's side, where the tunnel carries many
/// sessions.
pub fn endpoint(
    carrier: Connection,
    tagged: bool,
    config: Option<ServerConfig>,
) -> Result<Endpoint> {
    endpoint_over(Arc::new(carrier), tagged, config)
}

/// [`endpoint`], over any [`Carrier`].
pub fn endpoint_over(
    carrier: Arc<dyn Carrier>,
    tagged: bool,
    config: Option<ServerConfig>,
) -> Result<Endpoint> {
    let tunnel = Arc::new(Tunnel {
        carrier: carrier.clone(),
        tagged,
        inbox: Arc::default(),
    });
    let inbox = tunnel.inbox.clone();
    tokio::spawn(async move {
        // Ends when the carrier closes.
        while let Some(datagram) = carrier.read_datagram().await {
            let arrived = if tagged {
                untag(&datagram).map(|(session, packet)| (relayed_address(session), packet))
            } else {
                Some((relayed_address(0), datagram))
            };
            if let Some((from, packet)) = arrived {
                inbox.push(from, packet);
            }
        }
    });
    Ok(Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        config,
        tunnel,
        Arc::new(quinn::TokioRuntime),
    )?)
}

struct Tunnel {
    carrier: Arc<dyn Carrier>,
    tagged: bool,
    inbox: Arc<Inbox>,
}

impl fmt::Debug for Tunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tunnel({})", self.carrier.describe())
    }
}

#[derive(Default)]
struct Inbox {
    queue: Mutex<Queue>,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<(SocketAddr, Bytes)>,
    /// The endpoint waiting for a packet.
    waker: Option<Waker>,
}

/// Packets waiting to be read, at most. Past this the tunnel is being fed
/// faster than QUIC reads, and dropping is what a UDP socket would do.
const INBOX_LIMIT: usize = 4096;

impl Inbox {
    fn push(&self, from: SocketAddr, packet: Bytes) {
        let waker = {
            let mut queue = self.lock();
            if queue.packets.len() >= INBOX_LIMIT {
                return;
            }
            queue.packets.push_back((from, packet));
            queue.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for Tunnel {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let size = transmit.segment_size.unwrap_or(transmit.contents.len());
        for packet in transmit.contents.chunks(size.max(1)) {
            let datagram = if self.tagged {
                // Anything not to a relayed peer is not for this socket.
                let Some(session) = session_of(transmit.destination) else {
                    continue;
                };
                tag(session, packet)
            } else {
                Bytes::copy_from_slice(packet)
            };
            // A datagram that cannot go is a lost packet, which QUIC above
            // recovers from; as for a UDP socket, that is not an error.
            if !self.carrier.send_datagram(datagram) {
                tracing::trace!("relayed packet dropped");
            }
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut queue = self.inbox.lock();
        let mut count = 0;
        while count < bufs.len().min(meta.len()) {
            let Some((from, packet)) = queue.packets.pop_front() else {
                break;
            };
            let len = packet.len().min(bufs[count].len());
            bufs[count][..len].copy_from_slice(&packet[..len]);
            meta[count] = RecvMeta {
                addr: from,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            count += 1;
        }
        if count == 0 {
            queue.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(Ok(count))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok((Ipv6Addr::UNSPECIFIED, 0).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_roundtrip_through_addresses_and_tags() {
        for session in [0, 1, 7, u64::MAX] {
            let address = relayed_address(session);
            assert!(is_relayed(address));
            assert_eq!(session_of(address), Some(session));
            let (back, packet) = untag(&tag(session, b"quic")).expect("untag");
            assert_eq!((back, &packet[..]), (session, &b"quic"[..]));
        }
        assert!(!is_relayed("203.0.113.1:443".parse().expect("addr")));
        assert!(!is_relayed("[2001:db8::1]:443".parse().expect("addr")));
        assert!(untag(&Bytes::from_static(b"short")).is_none());
    }
}
