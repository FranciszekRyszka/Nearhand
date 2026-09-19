//! Grants: the server's word that a user may connect to a device, and how.
//!
//! A viewer signed in to the server asks it for a device; the server checks
//! the user's grants (user group → device group, with a role) and hands back
//! a [`SignedGrant`] for that one device, good for a few minutes. The viewer
//! presents it to the agent ([`crate::Control::Present`]), which checks the
//! signature against the server key it pinned when it was installed, and
//! lets the viewer in with the grant's role. The agent never has to reach
//! the server to decide.
//!
//! The signature covers [`SIGNING_CONTEXT`] followed by `grant`, the
//! postcard encoding of a [`Grant`], exactly as sent. Signing and checking
//! are in `nearhand_transport::grant`, beside the keys.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Put before the signed bytes, so a signature over a grant can never be
/// taken for a signature over anything else the server's key signs.
pub const SIGNING_CONTEXT: &[u8] = b"nearhand grant v1\0";

/// How long a grant is good for once issued: long enough to connect, not to
/// keep. The session it opens lasts as long as it lasts.
pub const LIFETIME_SECS: u64 = 5 * 60;

/// What a grant lets its user do on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Watch only.
    View,
    /// Watch, and use the keyboard, mouse and clipboard.
    Control,
    /// Control, and whatever else a session can do: privacy mode and file
    /// transfer, when they come.
    Full,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::View => "view",
            Role::Control => "control",
            Role::Full => "full",
        }
    }

    /// Whether the viewer's keyboard, mouse and clipboard reach the device.
    pub fn controls(self) -> bool {
        self >= Role::Control
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "view" => Ok(Role::View),
            "control" => Ok(Role::Control),
            "full" => Ok(Role::Full),
            other => Err(format!("{other} is not a role: view, control or full")),
        }
    }
}

/// What the server vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// SHA-256 of the device's certificate: the one device this is for.
    pub device: [u8; 32],
    /// Who, as the server knows them: shown to the person at the device.
    pub user: String,
    pub role: Role,
    /// Unix seconds, on the server's clock.
    pub issued_at: u64,
    pub expires_at: u64,
    /// Random, so the agent can tell a grant it has seen before.
    pub nonce: [u8; 16],
}

impl Grant {
    /// The encoding that is signed.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        postcard::to_stdvec(self).map_err(crate::Error::Encode)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        postcard::from_bytes(bytes).map_err(crate::Error::Decode)
    }
}

/// A grant and the server's signature over it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGrant {
    /// The postcard encoding of a [`Grant`], as signed.
    pub grant: Vec<u8>,
    /// Ed25519, over [`SIGNING_CONTEXT`] then `grant`.
    pub signature: Vec<u8>,
    /// The server's certificate, whose key signed it. The agent checks that
    /// it is the one it pinned before looking at the key inside.
    pub server_certificate: Vec<u8>,
}

impl SignedGrant {
    /// What the grant says, unchecked: for the viewer, which only shows it.
    /// The agent checks the signature first.
    pub fn claims(&self) -> Result<Grant, crate::Error> {
        Grant::from_bytes(&self.grant)
    }
}

impl fmt::Debug for SignedGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.claims() {
            Ok(grant) => write!(f, "SignedGrant({grant:?})"),
            Err(_) => f.write_str("SignedGrant(undecodable)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_order_and_parse() {
        assert!(Role::View < Role::Control && Role::Control < Role::Full);
        assert!(!Role::View.controls());
        assert!(Role::Control.controls() && Role::Full.controls());
        for role in [Role::View, Role::Control, Role::Full] {
            assert_eq!(role.as_str().parse::<Role>(), Ok(role));
        }
        assert!("admin".parse::<Role>().is_err());
    }

    #[test]
    fn claims_read_back() {
        let grant = Grant {
            device: [3; 32],
            user: "ada".into(),
            role: Role::Control,
            issued_at: 1_000,
            expires_at: 1_000 + LIFETIME_SECS,
            nonce: [9; 16],
        };
        let signed = SignedGrant {
            grant: postcard::to_stdvec(&grant).expect("encode"),
            signature: vec![0; 64],
            server_certificate: vec![1, 2, 3],
        };
        assert_eq!(signed.claims().expect("claims"), grant);
        let bytes = postcard::to_stdvec(&signed).expect("encode");
        let back: SignedGrant = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, signed);
    }
}
