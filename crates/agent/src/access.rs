//! The access password of an unattended machine: set when the agent is
//! installed, stored only as a salted hash on the machine, and checked by the
//! agent itself. The server never sees it, so a server alone cannot open a
//! session (`docs/security.md`).
//!
//! The hash is PBKDF2-HMAC-SHA256, deliberately slow: a check costs a few
//! hundred milliseconds, which is nothing to someone typing the password and
//! a lot to someone guessing it. Guessing online is slowed further: after a
//! few wrong passwords in a row, the agent refuses every attempt for a while,
//! and the while doubles each time.

use std::num::NonZeroU32;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::gate::{Gate, Verdict};

/// OWASP's recommendation for PBKDF2-HMAC-SHA256, as of 2023.
pub const ITERATIONS: u32 = 600_000;
/// Shorter passwords are refused when one is set: this one guards a machine
/// that nobody may be watching.
pub const MIN_LENGTH: usize = 10;
/// Wrong passwords in a row before the agent starts refusing for a while.
const FREE_FAILURES: u32 = 5;
const FIRST_LOCKOUT: Duration = Duration::from_secs(30);
const MAX_LOCKOUT: Duration = Duration::from_secs(15 * 60);

const ALGORITHM: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;

/// What is kept on disk: enough to check a password, not to recover it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stored {
    pub iterations: u32,
    /// Hex.
    pub salt: String,
    /// Hex.
    pub hash: String,
}

impl Stored {
    /// Hash `password` with a fresh salt.
    pub fn new(password: &str) -> anyhow::Result<Self> {
        if password.chars().count() < MIN_LENGTH {
            anyhow::bail!("the access password must be at least {MIN_LENGTH} characters");
        }
        let mut salt = [0u8; SALT_LEN];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("the system random number generator failed"))?;
        Ok(Self::with_salt(password, &salt, ITERATIONS))
    }

    fn with_salt(password: &str, salt: &[u8], iterations: u32) -> Self {
        let mut hash = [0u8; HASH_LEN];
        let rounds = NonZeroU32::new(iterations).unwrap_or(NonZeroU32::MIN);
        pbkdf2::derive(ALGORITHM, rounds, salt, password.as_bytes(), &mut hash);
        Self {
            iterations,
            salt: to_hex(salt),
            hash: to_hex(&hash),
        }
    }

    /// Whether `attempt` is the password. Takes as long whether it is or not.
    pub fn matches(&self, attempt: &str) -> bool {
        let (Some(salt), Some(hash), Some(rounds)) = (
            from_hex(&self.salt),
            from_hex(&self.hash),
            NonZeroU32::new(self.iterations),
        ) else {
            return false;
        };
        pbkdf2::verify(ALGORITHM, rounds, &salt, attempt.as_bytes(), &hash).is_ok()
    }
}

/// An access password in use, with its count of recent failures.
pub struct AccessPassword {
    stored: Stored,
    state: Mutex<Failures>,
}

#[derive(Default)]
struct Failures {
    in_a_row: u32,
    locked_until: Option<Instant>,
}

impl AccessPassword {
    pub fn new(stored: Stored) -> Self {
        Self {
            stored,
            state: Mutex::default(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Failures> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// How long a lockout after `in_a_row` failures lasts, if any.
    fn lockout(in_a_row: u32) -> Option<Duration> {
        let over = in_a_row.checked_sub(FREE_FAILURES)?;
        let doubled = FIRST_LOCKOUT.saturating_mul(1u32 << over.min(16));
        Some(doubled.min(MAX_LOCKOUT))
    }
}

impl Gate for AccessPassword {
    fn check(&self, attempt: &str) -> Verdict {
        let now = Instant::now();
        if let Some(until) = self.lock().locked_until
            && now < until
        {
            // Not even checked: a guess made now tells nothing.
            return Verdict::Rejected("too many wrong passwords; try again later");
        }
        // The slow part, outside the lock.
        let right = self.stored.matches(attempt);
        let mut state = self.lock();
        if right {
            *state = Failures::default();
            return Verdict::Accepted;
        }
        state.in_a_row += 1;
        state.locked_until = Self::lockout(state.in_a_row).map(|d| now + d);
        Verdict::Rejected("wrong password")
    }

    fn is_slow(&self) -> bool {
        true
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast enough for tests; the real count only changes the time taken.
    fn quick(password: &str) -> Stored {
        Stored::with_salt(password, b"0123456789abcdef", 1000)
    }

    #[test]
    fn the_password_matches_and_others_do_not() {
        let stored = quick("correct horse battery");
        assert!(stored.matches("correct horse battery"));
        assert!(!stored.matches("correct horse batterY"));
        assert!(!stored.matches(""));
    }

    #[test]
    fn salts_make_equal_passwords_hash_differently() {
        let a = Stored::new("the same password").expect("a");
        let b = Stored::new("the same password").expect("b");
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.hash, b.hash);
        assert_eq!(a.iterations, ITERATIONS);
        assert!(a.matches("the same password"));
    }

    #[test]
    fn short_passwords_are_refused() {
        assert!(Stored::new("123456789").is_err());
        assert!(Stored::new("1234567890").is_ok());
    }

    #[test]
    fn damaged_records_match_nothing() {
        let mut stored = quick("correct horse battery");
        stored.hash.pop();
        assert!(!stored.matches("correct horse battery"));
        let mut stored = quick("correct horse battery");
        stored.iterations = 0;
        assert!(!stored.matches("correct horse battery"));
    }

    #[test]
    fn stored_records_roundtrip_through_toml() {
        let stored = quick("correct horse battery");
        let text = toml::to_string(&stored).expect("serialize");
        assert_eq!(toml::from_str::<Stored>(&text).expect("parse"), stored);
    }

    #[test]
    fn repeated_failures_lock_the_door_for_longer_each_time() {
        assert_eq!(AccessPassword::lockout(FREE_FAILURES - 1), None);
        assert_eq!(AccessPassword::lockout(FREE_FAILURES), Some(FIRST_LOCKOUT));
        assert_eq!(
            AccessPassword::lockout(FREE_FAILURES + 1),
            Some(FIRST_LOCKOUT * 2)
        );
        assert_eq!(
            AccessPassword::lockout(FREE_FAILURES + 40),
            Some(MAX_LOCKOUT)
        );

        let access = AccessPassword::new(quick("correct horse battery"));
        for _ in 0..FREE_FAILURES {
            assert!(matches!(access.check("guess"), Verdict::Rejected(_)));
        }
        // Locked: even the right password is turned away for now.
        assert!(matches!(
            access.check("correct horse battery"),
            Verdict::Rejected(reason) if reason.contains("later")
        ));
    }

    #[test]
    fn a_success_clears_the_failures() {
        let access = AccessPassword::new(quick("correct horse battery"));
        for _ in 0..FREE_FAILURES - 1 {
            assert!(matches!(access.check("guess"), Verdict::Rejected(_)));
        }
        assert!(matches!(
            access.check("correct horse battery"),
            Verdict::Accepted
        ));
        for _ in 0..FREE_FAILURES - 1 {
            assert!(matches!(access.check("guess"), Verdict::Rejected(_)));
        }
        assert!(matches!(
            access.check("correct horse battery"),
            Verdict::Accepted
        ));
    }
}
