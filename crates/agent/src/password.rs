//! The one-time password that lets a viewer into a portable agent.
//!
//! The person at the host reads it out; the viewer types it; neither sends
//! it anywhere. The viewer proves it knows the password with the exchange
//! in `nearhand_core::access`, which the agent answers from the password it
//! is showing — so the server never sees it, and nor does anything else
//! between the two.
//!
//! Six digits is a million possibilities, and a wrong guess costs a whole
//! connection. After [`MAX_FAILURES`] wrong ones the password changes, so
//! guessing gets a handful of tries at each million, not an unlimited run.

use std::sync::Mutex;

use nearhand_core::access::Secret;
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
    fn secret(&self) -> Secret {
        Secret::OneTime
    }

    fn material(&self) -> Result<Vec<u8>, &'static str> {
        Ok(self.current().into_bytes())
    }

    fn accepted(&self) {
        self.lock().failures = 0;
    }

    fn rejected(&self) -> Verdict {
        let mut state = self.lock();
        state.failures += 1;
        if state.failures < MAX_FAILURES {
            return Verdict::Rejected("wrong password");
        }
        state.failures = 0;
        state.current = draw(&self.random);
        Verdict::Replaced(state.current.clone())
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

    /// What a viewer runs the exchange with is the password as read out,
    /// spaces and all.
    #[test]
    fn the_material_is_the_password_a_viewer_would_type() {
        let password = Password::new();
        let current = password.current();
        let spaced = format!("{} {}", &current[..3], &current[3..]);
        assert_eq!(
            password.material().expect("material"),
            Secret::OneTime.material(&spaced).expect("typed")
        );
    }

    #[test]
    fn too_many_failures_replace_it() {
        let password = Password::new();
        let old = password.current();
        for _ in 1..MAX_FAILURES {
            assert!(matches!(password.rejected(), Verdict::Rejected(_)));
        }
        let Verdict::Replaced(new) = password.rejected() else {
            panic!("not replaced after {MAX_FAILURES} failures");
        };
        assert_eq!(new, password.current());
        // A draw can land on the same six digits; what matters is that the
        // count started over.
        assert!(matches!(password.rejected(), Verdict::Rejected(_)), "{old}");
    }

    #[test]
    fn a_renewed_password_replaces_the_old_one() {
        let password = Password::new();
        let new = password.renew();
        assert_eq!(new, password.current());
        assert_eq!(password.material().expect("material"), new.into_bytes());
    }

    #[test]
    fn a_success_resets_the_count() {
        let password = Password::new();
        let current = password.current();
        for _ in 0..MAX_FAILURES * 3 {
            assert!(matches!(password.rejected(), Verdict::Rejected(_)));
            password.accepted();
        }
        assert_eq!(password.current(), current, "it was replaced after all");
    }
}
