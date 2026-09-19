//! Grants from the server this agent was installed with: a viewer signed in
//! there presents one instead of a password (`nearhand_core::grant`).
//!
//! The agent accepts a grant if the server it pinned signed it, it is for
//! this device, it is within its few minutes of validity, and it has not
//! been presented before. Then the grant's role says what the session may
//! do. The agent decides alone; it does not ask the server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use nearhand_core::grant::{Grant, SignedGrant};
use nearhand_transport::Fingerprint;
use nearhand_transport::grant::verify;

/// How far the server's clock and this machine's may disagree.
const CLOCK_SKEW_SECS: u64 = 2 * 60;

pub struct Grants {
    /// The server's certificate fingerprint, pinned at install.
    server: Fingerprint,
    /// This device's.
    device: Fingerprint,
    /// Nonces of grants taken, until they would have expired anyway.
    seen: Mutex<HashMap<[u8; 16], u64>>,
}

impl Grants {
    pub fn new(server: Fingerprint, device: Fingerprint) -> Self {
        Self {
            server,
            device,
            seen: Mutex::default(),
        }
    }

    /// The grant, if it lets its viewer in now.
    pub fn check(&self, signed: &SignedGrant) -> Result<Grant, &'static str> {
        self.check_at(signed, now())
    }

    fn check_at(&self, signed: &SignedGrant, now: u64) -> Result<Grant, &'static str> {
        let grant = verify(signed, self.server).map_err(|e| {
            tracing::info!(error = %e, "grant refused");
            "the grant is not from this device's server"
        })?;
        if grant.device != *self.device.as_bytes() {
            return Err("the grant is for another device");
        }
        if now + CLOCK_SKEW_SECS < grant.issued_at {
            return Err("the grant is not valid yet; check the clocks");
        }
        if now > grant.expires_at + CLOCK_SKEW_SECS {
            return Err("the grant has expired; ask the server for a new one");
        }
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, until| *until >= now);
        if seen.contains_key(&grant.nonce) {
            return Err("the grant was used already");
        }
        seen.insert(grant.nonce, grant.expires_at + CLOCK_SKEW_SECS);
        Ok(grant)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nearhand_core::grant::{LIFETIME_SECS, Role};
    use nearhand_transport::Identity;

    const T: u64 = 1_800_000_000;

    fn grant(device: Fingerprint, nonce: u8) -> Grant {
        Grant {
            device: *device.as_bytes(),
            user: "bob".into(),
            role: Role::Control,
            issued_at: T,
            expires_at: T + LIFETIME_SECS,
            nonce: [nonce; 16],
        }
    }

    #[test]
    fn a_fresh_grant_for_this_device_lets_in_once() {
        let server = Identity::generate().expect("server");
        let device = Fingerprint::from_bytes([7; 32]);
        let grants = Grants::new(server.fingerprint(), device);
        let signed = server.sign_grant(&grant(device, 1)).expect("sign");
        let taken = grants.check_at(&signed, T + 1).expect("accepted");
        assert_eq!(taken.user, "bob");
        assert_eq!(taken.role, Role::Control);
        assert!(grants.check_at(&signed, T + 2).is_err(), "not twice");
    }

    #[test]
    fn grants_for_elsewhere_or_other_times_are_refused() {
        let server = Identity::generate().expect("server");
        let device = Fingerprint::from_bytes([7; 32]);
        let grants = Grants::new(server.fingerprint(), device);

        let other_device = Fingerprint::from_bytes([8; 32]);
        let signed = server.sign_grant(&grant(other_device, 1)).expect("sign");
        assert!(grants.check_at(&signed, T).is_err());

        let impostor = Identity::generate().expect("impostor");
        let signed = impostor.sign_grant(&grant(device, 2)).expect("sign");
        assert!(grants.check_at(&signed, T).is_err());

        let signed = server.sign_grant(&grant(device, 3)).expect("sign");
        assert!(grants.check_at(&signed, T - CLOCK_SKEW_SECS - 1).is_err());
        assert!(
            grants
                .check_at(&signed, T + LIFETIME_SECS + CLOCK_SKEW_SECS + 1)
                .is_err()
        );
        assert!(
            grants.check_at(&signed, T - 60).is_ok(),
            "a minute's skew is forgiven"
        );
    }
}
