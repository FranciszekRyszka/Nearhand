//! Talking to the server: an agent registers and waits; a viewer asks for a
//! device by ID; the server introduces them and steps aside.
//!
//! ```text
//! agent            server             viewer
//!   Register  ──▶                                  (agent's key: its TLS client certificate)
//!             ◀──  Registered { id }
//!                              ◀──  Connect { id }
//!             ◀──  Incoming { session, viewer's addresses }
//!   (sends a packet to each, opening its own firewall to them)
//!   Ready     ──▶
//!                              ──▶  Peer { fingerprint, agent's addresses }
//!   ◀════════════ QUIC, viewer to agent, pinned to the fingerprint ════════════
//! ```
//!
//! The server vouches for which key belongs to an ID, and nothing else: it
//! never sees a session's contents or its password. Everything after `Peer`
//! runs between viewer and agent on the peer protocol, [`crate::ALPN`].

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Application-layer protocol name for connections to the server.
pub const SERVER_ALPN: &[u8] = b"nearhand-server/1";

/// A device's ID: ten digits, derived from its key.
///
/// Short enough to read out over the phone. Deriving it from the key, rather
/// than having the server hand one out, means a device keeps its ID for as
/// long as it keeps its key, on any server, with nothing stored anywhere.
///
/// It is a name, not a proof: ten digits are about 33 bits, and a malicious
/// server could find another key with the same ID in minutes. What the viewer
/// pins is the full fingerprint the server reports in [`FromServer::Peer`],
/// so the server is trusted to report it honestly (`docs/security.md`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeviceId(u64);

impl DeviceId {
    const MODULUS: u64 = 10_000_000_000;

    /// The ID for the key whose certificate has this SHA-256 fingerprint.
    pub fn from_fingerprint(fingerprint: &[u8; 32]) -> Self {
        let mut head = [0u8; 8];
        head.copy_from_slice(&fingerprint[..8]);
        Self(u64::from_be_bytes(head) % Self::MODULUS)
    }

    pub fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for DeviceId {
    /// `123 456 7890`: groups make ten digits easy to read and repeat.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = format!("{:010}", self.0);
        write!(f, "{} {} {}", &digits[..3], &digits[3..6], &digits[6..])
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({self})")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidDeviceId;

impl fmt::Display for InvalidDeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a device ID is ten digits")
    }
}

impl std::error::Error for InvalidDeviceId {}

impl FromStr for DeviceId {
    type Err = InvalidDeviceId;

    /// Ten digits, with any spaces or dashes people type between groups.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits: String = s.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
        if digits.len() != 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidDeviceId);
        }
        digits.parse().map(Self).map_err(|_| InvalidDeviceId)
    }
}

/// To the server, on the one bidirectional stream a client opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToServer {
    /// First message from an agent, which must have connected with its
    /// certificate: the ID is the one derived from it. `addresses` are where
    /// the agent can be reached on its own network; the server adds the
    /// address it sees.
    Register { addresses: Vec<SocketAddr> },
    /// First message from a viewer.
    Connect {
        id: DeviceId,
        addresses: Vec<SocketAddr>,
    },
    /// From an agent: it has opened its firewall to the viewer of `session`.
    Ready { session: u64 },
    /// From an agent: it will not take `session`.
    Decline { session: u64 },
}

/// From the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromServer {
    /// To an agent: registered, and the address the server sees it at.
    Registered {
        id: DeviceId,
        observed: SocketAddr,
    },
    /// To an agent: a viewer wants to connect from these addresses.
    Incoming {
        session: u64,
        addresses: Vec<SocketAddr>,
    },
    /// To a viewer: the device's certificate fingerprint, to pin, and where
    /// to find it.
    Peer {
        fingerprint: [u8; 32],
        addresses: Vec<SocketAddr>,
    },
    Refused(Refusal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// No device with that ID is connected to this server.
    Offline,
    /// An agent tried to register without a certificate.
    NoCertificate,
    /// Another key already holds this ID on this server. Rare — with ten
    /// thousand devices on one server, about a one-in-two-hundred chance that
    /// any two collide — and a fresh key gives a fresh ID.
    IdTaken,
    /// The agent declined, or did not answer in time.
    Declined,
    /// Too many attempts from this address; try again later.
    TooManyAttempts,
    /// The first message was not one this server expects.
    Protocol,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::Offline => "no device with that ID is online on this server",
            Refusal::NoCertificate => "the agent connected without its certificate",
            Refusal::IdTaken => "another device already holds this ID",
            Refusal::Declined => "the device did not accept the connection",
            Refusal::TooManyAttempts => "too many attempts; try again in a minute",
            Refusal::Protocol => "unexpected message",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + fmt::Debug,
    {
        let bytes = postcard::to_stdvec(value).expect("serialize");
        assert_eq!(
            &postcard::from_bytes::<T>(&bytes).expect("deserialize"),
            value
        );
    }

    #[test]
    fn ids_come_from_the_fingerprint_and_read_back() {
        let id = DeviceId::from_fingerprint(&[0xAB; 32]);
        assert!(id.value() < 10_000_000_000);
        assert_eq!(DeviceId::from_fingerprint(&[0xAB; 32]), id, "stable");
        assert_ne!(DeviceId::from_fingerprint(&[0xAC; 32]), id);

        let text = id.to_string();
        assert_eq!(text.len(), 12, "ten digits and two spaces: {text}");
        assert_eq!(text.parse::<DeviceId>(), Ok(id));
    }

    #[test]
    fn ids_keep_their_leading_zeros_and_forgive_separators() {
        let id = DeviceId(42);
        assert_eq!(id.to_string(), "000 000 0042");
        assert_eq!("000-000-0042".parse::<DeviceId>(), Ok(id));
        assert_eq!("0000000042".parse::<DeviceId>(), Ok(id));
        assert!("12345".parse::<DeviceId>().is_err());
        assert!("123 456 789x".parse::<DeviceId>().is_err());
        assert!("+123456789".parse::<DeviceId>().is_err());
    }

    #[test]
    fn messages_roundtrip() {
        let here: SocketAddr = "192.168.1.20:50000".parse().expect("addr");
        let v6: SocketAddr = "[2001:db8::1]:443".parse().expect("addr");
        roundtrip(&ToServer::Register {
            addresses: vec![here, v6],
        });
        roundtrip(&ToServer::Connect {
            id: DeviceId(1_234_567_890),
            addresses: vec![here],
        });
        roundtrip(&ToServer::Ready { session: 7 });
        roundtrip(&FromServer::Registered {
            id: DeviceId(1),
            observed: v6,
        });
        roundtrip(&FromServer::Peer {
            fingerprint: [9; 32],
            addresses: vec![here],
        });
        roundtrip(&FromServer::Refused(Refusal::Offline));
    }
}
