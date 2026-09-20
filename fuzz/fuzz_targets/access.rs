//! The password exchange, from the other side's point of view.
//!
//! An agent runs it with whoever connects, and a viewer with whatever
//! answered — before either knows the other knows the password. Both halves
//! take a curve point off the wire and a proof after it, so both are fed
//! arbitrary bytes here: as the message, and as the proof.
//!
//! The input is split into parts, each with a two-byte length: the
//! password, the channel binding, and the bytes to put through.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nearhand_core::access::{Agent, Secret, Seed, Viewer};

/// A length-prefixed part, and what is left after it.
fn part(rest: &[u8]) -> (&[u8], &[u8]) {
    let Some((header, body)) = rest.split_at_checked(2) else {
        return (rest, &[]);
    };
    let len = usize::from(u16::from_le_bytes([header[0], header[1]]));
    body.split_at(len.min(body.len()))
}

fuzz_target!(|data: &[u8]| {
    let (password, rest) = part(data);
    let (binding, rest) = part(rest);
    let (message, rest) = part(rest);
    let (proof, _) = part(rest);

    // What a one-time password stretches to, from arbitrary text.
    let _ = Secret::OneTime.material(&String::from_utf8_lossy(password));

    let seed = Seed([0x5A; 64]);
    if let Ok((agent, _answer)) = Agent::answer(password, binding, seed.clone(), message) {
        assert!(
            agent.check(proof).is_err(),
            "an agent took a proof from bytes alone"
        );
    }

    let (viewer, ours) = Viewer::start(password, binding, seed);
    // The viewer's own message is never one it should accept as an answer:
    // the two sides are marked apart.
    assert!(
        Viewer::start(password, binding, Seed([0x5A; 64]))
            .0
            .prove(&ours)
            .is_err(),
        "a viewer answered itself"
    );
    if let Ok((proven, _)) = viewer.prove(message) {
        assert!(
            proven.check(proof).is_err(),
            "a viewer took a proof from bytes alone"
        );
    }
});
