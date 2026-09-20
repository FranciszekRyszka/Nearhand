//! What a viewer must prove to be let in: the portable agent's one-time
//! password, or an installed agent's access password.
//!
//! Neither is ever sent to the agent. The viewer proves it knows the
//! password by running the exchange in `nearhand_core::access`, which needs
//! the material behind it — for a one-time password the digits, for an
//! access password the hash the agent stores — and this is where that comes
//! from.

use nearhand_core::access::Secret;

/// Holds what a viewer must know, and counts the attempts.
pub trait Gate: Send + Sync {
    /// What the viewer is told to prepare.
    fn secret(&self) -> Secret;

    /// The material to run the exchange with, or why there will be no
    /// exchange just now.
    fn material(&self) -> Result<Vec<u8>, &'static str>;

    /// The viewer proved it: forget the failures before it.
    fn accepted(&self);

    /// It did not, which may be one too many.
    fn rejected(&self) -> Verdict;
}

pub enum Verdict {
    /// Refused, and why, for the viewer.
    Rejected(&'static str),
    /// Refused, and that was one too many: here is the new password, for the
    /// person at the machine to read out.
    Replaced(String),
}
