//! A simulated internet for tests: hosts with public addresses, and hosts
//! behind NATs of the kinds found in the wild, all in one process. Real QUIC
//! endpoints run over it, so a test can show which NATs a connection gets
//! through without two machines and two routers.
//!
//! Each NAT has a public IP and a private network behind it. Hosts on the same
//! private network reach each other directly; everything else goes through the
//! NAT, which rewrites the source to its public IP and a port of its choosing,
//! and lets packets back in according to its kind. Packets from inside to the
//! NAT's own public address are dropped ("no hairpinning"), as on many cheap
//! routers. Delivery is instant and lossless.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

/// How a NAT maps sockets inside to ports outside, and whom it lets back in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatKind {
    /// One port per socket; anyone may send to it.
    FullCone,
    /// One port per socket; only IPs the socket has sent to may reply.
    AddressRestricted,
    /// One port per socket; only address and port pairs it has sent to may
    /// reply. The most common home router behaviour.
    PortRestricted,
    /// A new port for each destination, which only that destination may use.
    Symmetric,
}

#[derive(Default)]
pub struct Net {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// Every socket, by its own address: public, or private behind a NAT.
    sockets: HashMap<SocketAddr, Arc<Inbox>>,
    /// The NAT each private IP sits behind.
    realm: HashMap<IpAddr, IpAddr>,
    /// NATs by public IP.
    nats: HashMap<IpAddr, Nat>,
}

struct Nat {
    kind: NatKind,
    next_port: u16,
    /// Public port for (inside socket, destination — only when symmetric).
    ports: HashMap<(SocketAddr, Option<SocketAddr>), u16>,
    mappings: HashMap<u16, Mapping>,
}

struct Mapping {
    inside: SocketAddr,
    /// Everyone the inside socket has sent to through this port.
    sent_to: HashSet<SocketAddr>,
}

impl Nat {
    fn outbound(&mut self, inside: SocketAddr, to: SocketAddr) -> u16 {
        let key = (inside, (self.kind == NatKind::Symmetric).then_some(to));
        let port = match self.ports.get(&key) {
            Some(&port) => port,
            None => {
                let port = self.next_port;
                self.next_port += 1;
                self.ports.insert(key, port);
                self.mappings.insert(
                    port,
                    Mapping {
                        inside,
                        sent_to: HashSet::new(),
                    },
                );
                port
            }
        };
        if let Some(mapping) = self.mappings.get_mut(&port) {
            mapping.sent_to.insert(to);
        }
        port
    }

    /// The inside socket a packet from `from` to public `port` goes to, if the
    /// NAT lets it in.
    fn inbound(&self, port: u16, from: SocketAddr) -> Option<SocketAddr> {
        let mapping = self.mappings.get(&port)?;
        let allowed = match self.kind {
            NatKind::FullCone => true,
            NatKind::AddressRestricted => mapping.sent_to.iter().any(|a| a.ip() == from.ip()),
            NatKind::PortRestricted | NatKind::Symmetric => mapping.sent_to.contains(&from),
        };
        allowed.then_some(mapping.inside)
    }
}

impl Net {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    /// Put a NAT of `kind` on the internet at `public`, with its private
    /// network behind it.
    pub fn add_nat(&self, public: IpAddr, kind: NatKind) {
        self.lock().nats.insert(
            public,
            Nat {
                kind,
                next_port: 40_000,
                ports: HashMap::new(),
                mappings: HashMap::new(),
            },
        );
    }

    /// Make the NAT at `public` forget every mapping, as a router does when
    /// it restarts or times them out: sockets behind it get new ports.
    pub fn forget_mappings(&self, public: IpAddr) {
        if let Some(nat) = self.lock().nats.get_mut(&public) {
            nat.ports.clear();
            nat.mappings.clear();
        }
    }

    /// A socket at `address`, which is on the internet unless `behind` names
    /// a NAT's public IP, in which case `address` is private, behind it.
    pub fn socket(
        self: &Arc<Self>,
        address: SocketAddr,
        behind: Option<IpAddr>,
    ) -> Arc<dyn AsyncUdpSocket> {
        let inbox = Arc::new(Inbox::default());
        let mut state = self.lock();
        state.sockets.insert(address, inbox.clone());
        if let Some(nat) = behind {
            state.realm.insert(address.ip(), nat);
        }
        Arc::new(Socket {
            address,
            net: self.clone(),
            inbox,
        })
    }

    fn send(&self, from: SocketAddr, to: SocketAddr, packet: &[u8]) {
        let mut state = self.lock();
        let delivery = match state.realm.get(&from.ip()).copied() {
            // Same private network: straight there.
            Some(nat) if state.realm.get(&to.ip()) == Some(&nat) => Some((from, to)),
            // To this NAT's own public address from inside: dropped.
            Some(nat) if to.ip() == nat => None,
            // Out through the NAT.
            Some(nat) => {
                let port = state
                    .nats
                    .get_mut(&nat)
                    .map(|n| n.outbound(from, to))
                    .expect("a registered NAT");
                state.arrive(SocketAddr::new(nat, port), to)
            }
            None => state.arrive(from, to),
        };
        if let Some((source, inside)) = delivery
            && let Some(inbox) = state.sockets.get(&inside).cloned()
        {
            drop(state);
            inbox.push(source, packet);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl State {
    /// A packet from public `from` reaching public `to`: the (source, socket)
    /// it is delivered to, if any.
    fn arrive(&self, from: SocketAddr, to: SocketAddr) -> Option<(SocketAddr, SocketAddr)> {
        if self.realm.contains_key(&to.ip()) {
            return None; // private addresses are not routed on the internet
        }
        match self.nats.get(&to.ip()) {
            Some(nat) => nat.inbound(to.port(), from).map(|inside| (from, inside)),
            None => Some((from, to)),
        }
    }
}

#[derive(Default)]
struct Inbox {
    queue: Mutex<Queue>,
}

#[derive(Default)]
struct Queue {
    packets: VecDeque<(SocketAddr, Vec<u8>)>,
    /// The endpoint waiting for a packet.
    waker: Option<Waker>,
}

impl Inbox {
    fn push(&self, from: SocketAddr, packet: &[u8]) {
        let waker = {
            let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
            queue.packets.push_back((from, packet.to_vec()));
            queue.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

struct Socket {
    address: SocketAddr,
    net: Arc<Net>,
    inbox: Arc<Inbox>,
}

impl fmt::Debug for Socket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Socket({})", self.address)
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        let size = transmit.segment_size.unwrap_or(transmit.contents.len());
        for packet in transmit.contents.chunks(size.max(1)) {
            self.net.send(self.address, transmit.destination, packet);
        }
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut queue = self.inbox.queue.lock().unwrap_or_else(|p| p.into_inner());
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
                dst_ip: Some(self.address.ip()),
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
        Ok(self.address)
    }
}

/// An address on the simulated internet.
pub fn public(last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), port)
}

/// A private address, on network `network`.
pub fn private(network: u8, last: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, network, last)), port)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAT: u8 = 1;

    /// A socket behind a NAT of `kind`, a public host, and a second public
    /// host that the inside socket has not talked to.
    fn setup(kind: NatKind) -> (Arc<Net>, SocketAddr, SocketAddr, SocketAddr) {
        let net = Net::new();
        let nat_ip = public(NAT, 0).ip();
        net.add_nat(nat_ip, kind);
        let inside = private(1, 2, 5000);
        let a = public(10, 443);
        let b = public(11, 443);
        for (address, behind) in [(inside, Some(nat_ip)), (a, None), (b, None)] {
            net.socket(address, behind);
        }
        (net, inside, a, b)
    }

    fn received(net: &Net, at: SocketAddr) -> Vec<SocketAddr> {
        let inbox = net.lock().sockets[&at].clone();
        let mut queue = inbox.queue.lock().expect("lock");
        queue.packets.drain(..).map(|(from, _)| from).collect()
    }

    #[test]
    fn nats_rewrite_the_source_and_filter_by_kind() {
        for (kind, same_port_for_b, b_gets_in) in [
            (NatKind::FullCone, true, true),
            (NatKind::AddressRestricted, true, false),
            (NatKind::PortRestricted, true, false),
            (NatKind::Symmetric, false, false),
        ] {
            let (net, inside, a, b) = setup(kind);
            net.send(inside, a, b"hi");
            let [seen] = received(&net, a)[..] else {
                panic!("{kind:?}: nothing arrived at a");
            };
            assert_eq!(seen.ip(), public(NAT, 0).ip(), "{kind:?}");

            net.send(a, seen, b"back");
            assert_eq!(received(&net, inside), [a], "{kind:?}: a's reply");

            // b has not been sent to: only a full cone lets it in.
            net.send(b, seen, b"stranger");
            assert_eq!(!received(&net, inside).is_empty(), b_gets_in, "{kind:?}");

            // Sending to b: does b see the port a saw?
            net.send(inside, b, b"hi");
            assert_eq!(received(&net, b)[0] == seen, same_port_for_b, "{kind:?}");
        }
    }

    #[test]
    fn address_restricted_nats_take_any_port_of_a_known_host() {
        let (net, inside, a, _) = setup(NatKind::AddressRestricted);
        net.send(inside, a, b"hi");
        let seen = received(&net, a)[0];
        let other_port = SocketAddr::new(a.ip(), 9999);
        net.socket(other_port, None);
        net.send(other_port, seen, b"from elsewhere");
        assert_eq!(received(&net, inside), [other_port]);
    }

    #[test]
    fn private_networks_are_private() {
        let (net, inside, a, _) = setup(NatKind::FullCone);
        let neighbour = private(1, 3, 5000);
        net.socket(neighbour, Some(public(NAT, 0).ip()));
        net.send(neighbour, inside, b"lan");
        assert_eq!(received(&net, inside), [neighbour], "same network, direct");

        net.send(a, inside, b"not routed");
        assert!(received(&net, inside).is_empty());

        // Hairpin: to the NAT's own public address from inside.
        net.send(inside, a, b"map");
        let seen = received(&net, a)[0];
        net.send(neighbour, seen, b"hairpin");
        assert!(received(&net, inside).is_empty());
    }
}
