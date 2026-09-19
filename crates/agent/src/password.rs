//! The one-time password that lets a viewer into a portable agent.
//!
//! The person at the host reads it out; the viewer types it; the agent checks
//! it. The server never sees it, so a server alone cannot open a session.
//!
//! Six digits is a million possibilities, and a wrong guess costs a whole
//! connection. After [`MAX_FAILURES`] wrong ones the password changes, so
//! guessing gets a handful of tries at each million, not an unlimited run.

use std::sync::Mutex;

use ring::rand::{SecureRandom, SystemRandom};

use crate::gate::{Gate, Verdict};

const DIGITS: usize = 6;
pub const MAX_FAILURES: u32 = 3;

pub struct Password {
    state: Mutex<State>,
    random: SystemRandom,
}

struct State {
    current: String,
    failures: u32,
}

pub enum Check {
    Accepted,
    Rejected,
    /// Rejected, and that was one too many: here is the new password.
    Replaced(String),
}

impl Password {
    pub fn new() -> Self {
        let random = SystemRandom::new();
        let current = draw(&random);
        Self {
            state: Mutex::new(State {
                current,
                failures: 0,
            }),
            random,
        }
    }

    pub fn current(&self) -> String {
        self.lock().current.clone()
    }

    pub fn check(&self, attempt: &str) -> Check {
        let mut state = self.lock();
        // Spaces are how people read six digits out: "482 913".
        let attempt: String = attempt.chars().filter(|c| !c.is_whitespace()).collect();
        if attempt == state.current {
            state.failures = 0;
            return Check::Accepted;
        }
        state.failures += 1;
        if state.failures < MAX_FAILURES {
            return Check::Rejected;
        }
        state.failures = 0;
        state.current = draw(&self.random);
        Check::Replaced(state.current.clone())
    }

    /// Replace the password, at the host's request: whoever had the old one
    /// can no longer use it.
    pub fn renew(&self) -> String {
        let mut state = self.lock();
        state.failures = 0;
        state.current = draw(&self.random);
        state.current.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

impl Gate for Password {
    fn check(&self, attempt: &str) -> Verdict {
        match Password::check(self, attempt) {
            Check::Accepted => Verdict::Accepted,
            Check::Rejected => Verdict::Rejected("wrong password"),
            Check::Replaced(new) => Verdict::Replaced(new),
        }
    }
}

/// Six uniformly random digits. Drawn by rejection so every value is equally
/// likely: a plain modulo would favour the low ones slightly.
fn draw(random: &SystemRandom) -> String {
    const LIMIT: u32 = u32::MAX - u32::MAX % 1_000_000;
    loop {
        let mut bytes = [0u8; 4];
        if random.fill(&mut bytes).is_err() {
            // The OS random source failing is not something to limp on from.
            panic!("the system random number generator failed");
        }
        let value = u32::from_le_bytes(bytes);
        if value < LIMIT {
            return format!("{:0width$}", value % 1_000_000, width = DIGITS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords_are_six_digits_and_vary() {
        let a = Password::new().current();
        assert_eq!(a.len(), 6);
        assert!(a.bytes().all(|b| b.is_ascii_digit()));
        let others: Vec<String> = (0..5).map(|_| Password::new().current()).collect();
        assert!(others.iter().any(|o| *o != a), "six draws all equal");
    }

    #[test]
    fn the_right_password_passes_with_or_without_spaces() {
        let password = Password::new();
        let current = password.current();
        let spaced = format!("{} {}", &current[..3], &current[3..]);
        assert!(matches!(password.check(&spaced), Check::Accepted));
        assert!(matches!(password.check(&current), Check::Accepted));
    }

    #[test]
    fn too_many_failures_replace_it() {
        let password = Password::new();
        let old = password.current();
        let wrong = if old == "000000" { "111111" } else { "000000" };
        for _ in 1..MAX_FAILURES {
            assert!(matches!(password.check(wrong), Check::Rejected));
        }
        let Check::Replaced(new) = password.check(wrong) else {
            panic!("not replaced after {MAX_FAILURES} failures");
        };
        assert_eq!(new, password.current());
        assert!(matches!(password.check(&old), Check::Rejected) || new == old);
    }

    #[test]
    fn a_renewed_password_replaces_the_old_one() {
        let password = Password::new();
        let old = password.current();
        let new = password.renew();
        assert_eq!(new, password.current());
        if new != old {
            assert!(matches!(password.check(&old), Check::Rejected));
        }
        assert!(matches!(password.check(&new), Check::Accepted));
    }

    #[test]
    fn a_success_resets_the_count() {
        let password = Password::new();
        let current = password.current();
        let wrong = if current == "000000" {
            "111111"
        } else {
            "000000"
        };
        for _ in 0..MAX_FAILURES * 3 {
            assert!(matches!(password.check(wrong), Check::Rejected));
            assert!(matches!(password.check(&current), Check::Accepted));
        }
    }
}
