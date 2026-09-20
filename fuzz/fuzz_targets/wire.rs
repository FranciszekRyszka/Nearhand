//! Every decoder that bytes off the network reach.
//!
//! A message arrives on a QUIC stream as a length prefix and a postcard
//! body. Whoever sends it may be hostile, so no input may panic the
//! process: a malformed message is an error the caller closes the
//! connection over.
//!
//! The standing version of this, on stable and in every build, is
//! `crates/core/tests/hostile.rs`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nearhand_core::grant::Grant;
use nearhand_core::release::Release;
use nearhand_core::rendezvous::{Enrollment, FromServer, ToServer};
use nearhand_core::video::decode_chunk;
use nearhand_core::{Clipboard, Control, Cursor, Input, Monitor, StreamKind, wire};

fn decode_every_way(bytes: &[u8]) {
    let _ = wire::decode::<Control>(bytes);
    let _ = wire::decode::<ToServer>(bytes);
    let _ = wire::decode::<FromServer>(bytes);
    let _ = wire::decode::<Input>(bytes);
    let _ = wire::decode::<Clipboard>(bytes);
    let _ = wire::decode::<Cursor>(bytes);
    let _ = wire::decode::<StreamKind>(bytes);
    let _ = wire::decode::<Enrollment>(bytes);
    let _ = wire::decode::<Vec<Monitor>>(bytes);
    let _ = Grant::from_bytes(bytes);
    let _ = Release::from_bytes(bytes);
    let _ = decode_chunk(bytes);
}

fuzz_target!(|data: &[u8]| {
    decode_every_way(data);

    // The same bytes again as a reader takes them off a stream: a prefix
    // first, then as many bytes as it says.
    if let Some((header, body)) = data.split_at_checked(wire::HEADER_LEN) {
        let header: [u8; wire::HEADER_LEN] = header.try_into().expect("split at the header");
        if let Ok(len) = wire::body_len(header) {
            assert!(
                len <= wire::MAX_MESSAGE_LEN,
                "a length over the cap was accepted: {len}"
            );
            decode_every_way(&body[..len.min(body.len())]);
        }
    }
});
