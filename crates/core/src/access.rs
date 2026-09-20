//! Proving a password to an agent without sending it.
//!
//! A viewer is told where a device is, and what key it has, by a server. A
//! server that lies can answer with a key of its own and sit in the middle
//! of the session — and then it reads the password the viewer types, and an
//! access password lasts (`docs/security.md`).
//!
//! So the password is not sent. Viewer and agent run SPAKE2, a
//! password-authenticated key exchange: each sends one message, both arrive
//! at the same key if and only if they used the same password, and then
//! each proves to the other that it did. Watching the exchange tells an
//! onlooker nothing about the password, and standing in the middle of it is
//! worth one guess per connection — which is what the agent's lockouts are
//! for.
//!
//! What ties an exchange to *this* connection is `binding`: keying material
//! exported from the TLS session underneath (RFC 5705). Both ends of one
//! connection derive the same bytes; a server holding two connections, one
//! to each end, derives different ones on each. Without it such a server
//! could pass the exchange through untouched and still sit in the middle of
//! everything that follows. With it, the proofs do not match, and both ends
//! stop.
//!
//! The material the exchange runs with is not the password as typed. An
//! installed agent keeps only a PBKDF2 hash of its access password, so that
//! hash is what both sides use, and the viewer is told the salt and the
//! iteration count to arrive at it ([`Secret`]). A portable agent's
//! one-time password is short-lived and never stored, so it is used as it
//! is read out.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;

/// How much keying material both sides tie their proofs to.
pub const BINDING_LEN: usize = 32;
/// The label to export it under, so that nothing else in the protocol can
/// be made to produce the same bytes.
pub const BINDING_LABEL: &[u8] = b"nearhand access binding v1";
/// Length of each side's proof.
pub const PROOF_LEN: usize = 32;

/// Named in the exchange, so that one side's message cannot be replayed to
/// the other.
const VIEWER: &[u8] = b"nearhand-viewer";
const AGENT: &[u8] = b"nearhand-agent";
/// The keys the two proofs are taken under.
const VIEWER_PROOF: &[u8] = b"nearhand access viewer proof v1";
const AGENT_PROOF: &[u8] = b"nearhand access agent proof v1";
/// Opens the transcript the proofs cover.
const TRANSCRIPT: &[u8] = b"nearhand access v1";

/// What the viewer must know, and how to prepare it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Secret {
    /// The one-time password the agent shows the person at the machine,
    /// used as it is read out.
    OneTime,
    /// An installed agent's access password, stretched into what the agent
    /// keeps.
    Access { salt: Vec<u8>, iterations: u32 },
}

impl Secret {
    /// Salts are sixteen bytes; the limit is only to bound what a stranger
    /// claiming to be an agent can set a viewer to work on.
    pub const MAX_SALT: usize = 64;
    /// As is this: 600,000 is what an agent uses, and ten times that is
    /// already a wait no honest agent asks for.
    pub const MAX_ITERATIONS: u32 = 6_000_000;

    /// What the exchange runs with, from what the person typed. Slow for
    /// [`Secret::Access`] — hundreds of milliseconds, on purpose — so it
    /// does not belong on a thread with anything else to answer for.
    pub fn material(&self, typed: &str) -> Result<Vec<u8>, Refused> {
        match self {
            // Six digits get read out in groups: "482 913".
            Self::OneTime => Ok(typed
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .into_bytes()),
            Self::Access { salt, iterations } => {
                if salt.is_empty() || salt.len() > Self::MAX_SALT {
                    return Err(Refused::Unreasonable);
                }
                if *iterations == 0 || *iterations > Self::MAX_ITERATIONS {
                    return Err(Refused::Unreasonable);
                }
                let mut out = [0u8; 32];
                pbkdf2::pbkdf2_hmac::<Sha256>(typed.as_bytes(), salt, *iterations, &mut out);
                Ok(out.to_vec())
            }
        }
    }
}

/// What an agent asks of a viewer before it shows anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Required {
    /// This password, or a grant from the agent's server: either alone.
    Either(Secret),
    /// This password. The agent takes no grants: it was installed without
    /// a server's token, so no server can open it.
    Password(Secret),
    /// A grant from the agent's server. The agent has no password.
    Grant,
    /// A grant *and* this password. A server that was taken over can sign
    /// itself a grant for every machine enrolled with it, but it does not
    /// know their passwords (`docs/security.md`).
    Both(Secret),
}

impl Required {
    /// The password to prove, if any.
    pub fn secret(&self) -> Option<&Secret> {
        match self {
            Self::Either(secret) | Self::Password(secret) | Self::Both(secret) => Some(secret),
            Self::Grant => None,
        }
    }

    /// Whether a password alone gets a viewer in.
    pub fn password_is_enough(&self) -> bool {
        matches!(self, Self::Either(_) | Self::Password(_))
    }

    /// Whether a grant alone does.
    pub fn grant_is_enough(&self) -> bool {
        matches!(self, Self::Either(_) | Self::Grant)
    }

    /// Whether this agent takes grants at all.
    pub fn takes_grants(&self) -> bool {
        !matches!(self, Self::Password(_))
    }

    /// Whether a grant must be followed by the password.
    pub fn password_after_grant(&self) -> bool {
        matches!(self, Self::Both(_))
    }
}

/// Why an exchange ended without a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    #[error("the other side's message is not a SPAKE2 message")]
    Malformed,
    #[error("the password does not match, or something is in the middle")]
    NoMatch,
    #[error("the agent asks for a stretch no honest agent asks for")]
    Unreasonable,
}

/// Randomness for one exchange, from the caller: this crate has none of its
/// own, because it runs in a browser as well as on a machine. Sixty-four
/// bytes, fresh every time — a seed used twice gives the password away.
#[derive(Clone)]
pub struct Seed(pub [u8; 64]);

/// The viewer's half, before the agent has answered.
pub struct Viewer {
    state: Spake2<Ed25519Group>,
    binding: Vec<u8>,
    ours: Vec<u8>,
}

impl Viewer {
    /// Begin, with the material from [`Secret::material`]. The message
    /// returned goes to the agent.
    pub fn start(material: &[u8], binding: &[u8], seed: Seed) -> (Self, Vec<u8>) {
        let (state, ours) = Spake2::<Ed25519Group>::start_a_with_rng(
            &Password::new(material),
            &Identity::new(VIEWER),
            &Identity::new(AGENT),
            Stream::new(seed),
        );
        (
            Self {
                state,
                binding: binding.to_vec(),
                ours: ours.clone(),
            },
            ours,
        )
    }

    /// Take the agent's message, and give back the proof to send.
    pub fn prove(self, theirs: &[u8]) -> Result<(Proven, [u8; PROOF_LEN]), Refused> {
        let key = self.state.finish(theirs).map_err(|_| Refused::Malformed)?;
        let transcript = transcript(&self.ours, theirs, &self.binding);
        let ours = proof(&key, &self.binding, VIEWER_PROOF, &transcript);
        let theirs = proof(&key, &self.binding, AGENT_PROOF, &transcript);
        Ok((Proven { theirs }, ours))
    }
}

/// The viewer's half, waiting for the agent to prove itself in turn.
pub struct Proven {
    theirs: [u8; PROOF_LEN],
}

impl Proven {
    /// Check the agent's proof. Without it a viewer knows the password
    /// reached *something*, not that it reached the agent.
    pub fn check(self, theirs: &[u8]) -> Result<(), Refused> {
        same(&self.theirs, theirs)
    }
}

/// The agent's half, after answering the viewer.
pub struct Agent {
    theirs: [u8; PROOF_LEN],
    ours: [u8; PROOF_LEN],
}

impl Agent {
    /// Answer the viewer's message: what to send back, and the half that
    /// checks what comes next.
    pub fn answer(
        material: &[u8],
        binding: &[u8],
        seed: Seed,
        theirs: &[u8],
    ) -> Result<(Self, Vec<u8>), Refused> {
        let (state, ours) = Spake2::<Ed25519Group>::start_b_with_rng(
            &Password::new(material),
            &Identity::new(VIEWER),
            &Identity::new(AGENT),
            Stream::new(seed),
        );
        let key = state.finish(theirs).map_err(|_| Refused::Malformed)?;
        let transcript = transcript(theirs, &ours, binding);
        Ok((
            Self {
                theirs: proof(&key, binding, VIEWER_PROOF, &transcript),
                ours: proof(&key, binding, AGENT_PROOF, &transcript),
            },
            ours,
        ))
    }

    /// Check the viewer's proof, and give the agent's own to send back.
    pub fn check(self, theirs: &[u8]) -> Result<[u8; PROOF_LEN], Refused> {
        same(&self.theirs, theirs)?;
        Ok(self.ours)
    }
}

/// Everything both sides agree on, in an order neither can bend.
fn transcript(viewer: &[u8], agent: &[u8], binding: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSCRIPT.len() + viewer.len() + agent.len() + binding.len());
    out.extend_from_slice(TRANSCRIPT);
    for part in [viewer, agent, binding] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// One side's proof: a MAC over the transcript, under a key taken from the
/// exchange with the channel binding as the salt.
fn proof(key: &[u8], binding: &[u8], whose: &[u8], transcript: &[u8]) -> [u8; PROOF_LEN] {
    let mut mac_key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(binding), key)
        .expand(whose, &mut mac_key)
        .expect("32 bytes is a length HKDF expands to");
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).expect("HMAC takes a key of any length");
    mac.update(transcript);
    mac.finalize().into_bytes().into()
}

fn same(ours: &[u8], theirs: &[u8]) -> Result<(), Refused> {
    if ours.ct_eq(theirs).into() {
        Ok(())
    } else {
        Err(Refused::NoMatch)
    }
}

/// The seed, as the random numbers SPAKE2 asks for: HKDF over it, a block
/// per call. It is asked once, for the sixty-four bytes of a scalar; the
/// counter is there so that asking twice would still give different bytes.
struct Stream {
    hkdf: Hkdf<Sha256>,
    block: u32,
}

impl Stream {
    fn new(seed: Seed) -> Self {
        Self {
            hkdf: Hkdf::<Sha256>::new(None, &seed.0),
            block: 0,
        }
    }
}

impl rand_core::RngCore for Stream {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // HKDF gives at most 8160 bytes at once, and SPAKE2 asks for 64.
        for chunk in dest.chunks_mut(8160) {
            let info = self.block.to_be_bytes();
            self.block += 1;
            self.hkdf
                .expand(&info, chunk)
                .expect("a chunk is within what HKDF expands to");
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Stream {}

#[cfg(test)]
mod tests {
    use super::*;

    fn seeds() -> (Seed, Seed) {
        (Seed([7; 64]), Seed([9; 64]))
    }

    /// One exchange, as the two sides run it.
    fn exchange(
        viewer_material: &[u8],
        viewer_binding: &[u8],
        agent_material: &[u8],
        agent_binding: &[u8],
    ) -> Result<(), Refused> {
        let (viewer_seed, agent_seed) = seeds();
        let (viewer, to_agent) = Viewer::start(viewer_material, viewer_binding, viewer_seed);
        let (agent, to_viewer) =
            Agent::answer(agent_material, agent_binding, agent_seed, &to_agent)?;
        let (viewer, viewers_proof) = viewer.prove(&to_viewer)?;
        let agents_proof = agent.check(&viewers_proof)?;
        viewer.check(&agents_proof)
    }

    #[test]
    fn the_same_password_on_the_same_connection_agrees() {
        exchange(
            b"a password",
            b"the same connection",
            b"a password",
            b"the same connection",
        )
        .expect("both sides agree");
    }

    #[test]
    fn a_wrong_password_proves_nothing() {
        assert_eq!(
            exchange(
                b"a guess",
                b"one connection",
                b"a password",
                b"one connection"
            ),
            Err(Refused::NoMatch)
        );
    }

    /// The whole point: a server that passes the exchange through between
    /// two connections of its own holds two different bindings, and neither
    /// side's proof means anything to the other.
    #[test]
    fn the_exchange_does_not_carry_across_a_server_in_the_middle() {
        assert_eq!(
            exchange(
                b"a password",
                b"the viewer's connection",
                b"a password",
                b"the agent's connection"
            ),
            Err(Refused::NoMatch)
        );
    }

    #[test]
    fn a_message_that_is_not_one_is_an_error_not_a_panic() {
        let (viewer_seed, agent_seed) = seeds();
        let (viewer, to_agent) = Viewer::start(b"a password", b"a connection", viewer_seed);
        assert!(matches!(
            Agent::answer(b"a password", b"a connection", agent_seed, b"rubbish"),
            Err(Refused::Malformed)
        ));
        assert!(matches!(viewer.prove(b""), Err(Refused::Malformed)));
        // A message of the right length, with the wrong side's marker.
        let mut wrong = to_agent.clone();
        wrong[0] = b'A';
        let (viewer, _) = Viewer::start(b"a password", b"a connection", Seed([3; 64]));
        assert!(matches!(viewer.prove(&wrong), Err(Refused::Malformed)));
    }

    #[test]
    fn a_tampered_proof_is_refused() {
        let (viewer_seed, agent_seed) = seeds();
        let (viewer, to_agent) = Viewer::start(b"a password", b"a connection", viewer_seed);
        let (agent, to_viewer) =
            Agent::answer(b"a password", b"a connection", agent_seed, &to_agent).expect("answer");
        let (_viewer, mut viewers_proof) = viewer.prove(&to_viewer).expect("prove");
        viewers_proof[0] ^= 1;
        assert_eq!(agent.check(&viewers_proof), Err(Refused::NoMatch));
    }

    #[test]
    fn two_exchanges_of_the_same_password_look_nothing_alike() {
        let (viewer, first) = Viewer::start(b"a password", b"a connection", Seed([1; 64]));
        let (_, second) = Viewer::start(b"a password", b"a connection", Seed([2; 64]));
        assert_ne!(first, second);
        drop(viewer);
    }

    #[test]
    fn a_one_time_password_is_taken_as_it_is_read_out() {
        let material = Secret::OneTime.material(" 482 913 ").expect("material");
        assert_eq!(material, b"482913");
    }

    #[test]
    fn an_access_password_is_stretched_the_way_the_agent_stored_it() {
        let secret = Secret::Access {
            salt: b"0123456789abcdef".to_vec(),
            iterations: 1_000,
        };
        let material = secret.material("correct horse battery").expect("material");
        assert_eq!(material.len(), 32);
        // The same password and salt give the same material, and another
        // password does not.
        assert_eq!(
            secret.material("correct horse battery").expect("again"),
            material
        );
        assert_ne!(
            secret.material("correct horse batterY").expect("other"),
            material
        );
    }

    #[test]
    fn a_stretch_no_agent_would_ask_for_is_refused() {
        for secret in [
            Secret::Access {
                salt: Vec::new(),
                iterations: 1_000,
            },
            Secret::Access {
                salt: vec![0; Secret::MAX_SALT + 1],
                iterations: 1_000,
            },
            Secret::Access {
                salt: b"0123456789abcdef".to_vec(),
                iterations: 0,
            },
            Secret::Access {
                salt: b"0123456789abcdef".to_vec(),
                iterations: Secret::MAX_ITERATIONS + 1,
            },
        ] {
            assert_eq!(secret.material("a password"), Err(Refused::Unreasonable));
        }
    }
}
