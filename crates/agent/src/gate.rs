//! What a viewer must say to be let in: the portable agent's one-time
//! password, or an installed agent's access password.

/// Checks a password a viewer gave.
pub trait Gate: Send + Sync {
    fn check(&self, attempt: &str) -> Verdict;

    /// Whether a check takes long enough to belong off the async threads.
    fn is_slow(&self) -> bool {
        false
    }
}

pub enum Verdict {
    Accepted,
    /// Refused, and why, for the viewer.
    Rejected(&'static str),
    /// Refused, and that was one too many: here is the new password, for the
    /// person at the machine to read out.
    Replaced(String),
}
