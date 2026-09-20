//! What a password exchange (`nearhand_core::access`) needs from a QUIC
//! connection: the keying material that ties it to this connection, and
//! fresh randomness for it.
//!
//! The browser viewer does the same two things with `quinn-proto` and the
//! browser's own random numbers; this is for everything that speaks over
//! `quinn`.

use nearhand_core::access::{BINDING_LABEL, BINDING_LEN, Seed};
use quinn::Connection;
use ring::rand::{SecureRandom, SystemRandom};

use crate::{Error, Result};

/// The bytes both ends of *this* connection derive, and nothing holding a
/// connection to each end can.
pub fn binding(conn: &Connection) -> Result<[u8; BINDING_LEN]> {
    let mut out = [0u8; BINDING_LEN];
    conn.export_keying_material(&mut out, BINDING_LABEL, b"")
        .map_err(|_| Error::Config("this connection exports no keying material".to_owned()))?;
    Ok(out)
}

/// Randomness for one exchange. Never reused: a repeated seed gives the
/// password away.
pub fn seed() -> Result<Seed> {
    let mut bytes = [0u8; 64];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Error::Config("the system random number generator failed".to_owned()))?;
    Ok(Seed(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_differ() {
        let (a, b) = (seed().expect("a"), seed().expect("b"));
        assert_ne!(a.0, b.0);
        assert_ne!(a.0, [0; 64]);
    }
}
