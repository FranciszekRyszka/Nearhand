//! The signature file that travels beside a release package.
//!
//! Two lines of hex, written by the release tool and read by the server,
//! the tool and anyone checking a download by hand — so it is parsed from
//! whatever a disk or a download holds. What parses must survive a round
//! trip: a file that reads back as something else would make "verified"
//! mean two things.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nearhand_core::release::SignedRelease;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let Ok(signed) = SignedRelease::from_text(&text) else {
        return;
    };
    let written = signed.to_text();
    let again = SignedRelease::from_text(&written).expect("what was just written parses");
    assert_eq!(again.release, signed.release, "the release changed");
    assert_eq!(again.signature, signed.signature, "the signature changed");
    // Reading what it claims never panics, whether or not it decodes.
    let _ = signed.claims();
});
