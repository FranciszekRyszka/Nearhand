//! Checking signatures on grants and releases.
//!
//! Both arrive from elsewhere — a grant with the certificate it was signed
//! under, a release with the signature over it — and both are parsed before
//! anything is known to be genuine. The input is split into three parts,
//! each with a two-byte length, so a run can put arbitrary bytes into a
//! certificate, a body and a signature at once.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nearhand_core::grant::SignedGrant;
use nearhand_core::release::{self, SignedRelease};
use nearhand_transport::{Fingerprint, grant, release as signing};
use rustls::pki_types::CertificateDer;

/// A length-prefixed part, and what is left after it.
fn part(rest: &[u8]) -> (&[u8], &[u8]) {
    let Some((header, body)) = rest.split_at_checked(2) else {
        return (rest, &[]);
    };
    let len = usize::from(u16::from_le_bytes([header[0], header[1]]));
    body.split_at(len.min(body.len()))
}

fuzz_target!(|data: &[u8]| {
    let (certificate, rest) = part(data);
    let (body, rest) = part(rest);
    let (signature, _) = part(rest);

    let signed = SignedGrant {
        grant: body.to_vec(),
        signature: signature.to_vec(),
        server_certificate: certificate.to_vec(),
    };
    // The fingerprint of the certificate in hand, so that the check goes on
    // to the key and the signature rather than stopping at "another
    // server".
    let pinned = Fingerprint::of(&CertificateDer::from(certificate));
    if let Ok(claims) = grant::verify(&signed, pinned) {
        assert_eq!(
            claims,
            signed.claims().expect("a verified grant reads back"),
            "a grant verified as something other than what it says"
        );
    }
    let _ = grant::verify(&signed, Fingerprint::from_bytes([0; 32]));

    let signed = SignedRelease {
        release: body.to_vec(),
        signature: signature.to_vec(),
    };
    if let Ok(claims) = signing::verify(&signed, &release::KEY) {
        assert_eq!(
            claims,
            signed.claims().expect("a verified release reads back"),
            "a release verified as something other than what it says"
        );
        let _ = signing::check_package(&claims, certificate);
    }
});
