//! The video reassembler, driven by datagrams no sender would send.
//!
//! Frames arrive in QUIC datagrams, which may be lost, reordered,
//! duplicated or forged; the reassembler holds state across all of them and
//! asks for what is missing. The input here is a run of datagrams — two
//! bytes of length, then that many bytes — with the clock stepped between
//! them, so a run drives the repair and expiry timers as well as the
//! decoding.
//!
//! After the run it is fed one good frame: whatever it was put through, it
//! must still work.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nearhand_core::video::{Reassembler, Timing, decode_chunk, encode_chunk, packetize};

/// As a viewer sets them from a round trip of a few milliseconds.
const TIMING: Timing = Timing {
    quiet_us: 10_000,
    retry_us: 20_000,
    give_up_us: 100_000,
};

/// The next datagram, and what is left after it.
fn next_datagram(rest: &[u8]) -> Option<(&[u8], &[u8])> {
    let (header, body) = rest.split_at_checked(2)?;
    let len = usize::from(u16::from_le_bytes([header[0], header[1]]));
    Some(body.split_at(len.min(body.len())))
}

fuzz_target!(|data: &[u8]| {
    let mut reassembler = Reassembler::new();
    let mut rest = data;
    let mut now = 0u64;
    while let Some((datagram, tail)) = next_datagram(rest) {
        rest = tail;
        // Stepped by the datagram itself, so a run can stand still, creep,
        // or jump past every deadline at once.
        now += u64::from(datagram.first().copied().unwrap_or(0)) * 1_000;
        if let Ok(chunk) = decode_chunk(datagram) {
            reassembler.push(chunk, now);
        }
        let _ = reassembler.pop();
        let _ = reassembler.nacks(now, &TIMING);
        reassembler.expire(now, &TIMING);
        let _ = reassembler.next_deadline(&TIMING);
        let _ = reassembler.take_keyframe_request();
        let _ = reassembler.stats();
    }

    // Still usable: a good keyframe pushed now comes back whole. Unless the
    // run left no room for one of that id — it is settled already, or parts
    // of it are in hand — which the counters say, and then there is nothing
    // to assert.
    let payload: Vec<u8> = (0..900u32).map(|i| i as u8).collect();
    let before = reassembler.stats();
    for chunk in packetize(1, true, now, &payload.clone().into(), 1200).expect("packetize") {
        let encoded = encode_chunk(&chunk).expect("encode");
        let chunk = decode_chunk(&encoded).expect("decode what was just encoded");
        reassembler.push(chunk, now);
    }
    let after = reassembler.stats();
    if after.late_chunks > before.late_chunks
        || after.invalid_chunks > before.invalid_chunks
        || after.duplicate_chunks > before.duplicate_chunks
    {
        return;
    }
    // Anything older it was still waiting for is now past waiting for.
    reassembler.expire(now.saturating_add(100 * TIMING.give_up_us), &TIMING);
    let mut delivered = false;
    while let Some(frame) = reassembler.pop() {
        delivered |= frame.data.as_ref() == payload.as_slice();
    }
    assert!(delivered, "a good keyframe did not come through: {after:?}");
});
