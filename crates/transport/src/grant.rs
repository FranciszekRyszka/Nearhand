//! Signing grants on the server and checking them on the agent
//! (`nearhand_core::grant`).
//!
//! The server signs with the Ed25519 key behind its certificate — the one
//! agents pin — so an agent needs nothing new to check a grant: it confirms
//! the certificate that comes with the grant is the one it pinned, takes the
//! public key out of it, and checks the signature.

use nearhand_core::grant::{Grant, SIGNING_CONTEXT, SignedGrant};
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};

use crate::{Error, Fingerprint, Identity, Result};

/// The DER that comes before an Ed25519 key in a certificate: the
/// SubjectPublicKeyInfo header, with the algorithm's OID (1.3.101.112).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

impl Identity {
    /// Sign `grant` with this identity's key.
    pub fn sign_grant(&self, grant: &Grant) -> Result<SignedGrant> {
        let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(self.key.secret_pkcs8_der())
            .map_err(|e| Error::Config(format!("the key cannot sign: {e}")))?;
        let grant = grant.to_bytes()?;
        let signature = key.sign(&signed_bytes(&grant)).as_ref().to_vec();
        Ok(SignedGrant {
            grant,
            signature,
            server_certificate: self.cert.to_vec(),
        })
    }
}

/// Why a grant was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    #[error("the grant is from another server")]
    OtherServer,
    #[error("the grant's signature is wrong")]
    Signature,
    #[error("the grant cannot be read")]
    Malformed,
}

/// What `signed` says, if the server whose certificate has the fingerprint
/// `server` signed it. Whether it is for this device, and still valid, is
/// for the caller to check.
pub fn verify(signed: &SignedGrant, server: Fingerprint) -> std::result::Result<Grant, Invalid> {
    let certificate = rustls::pki_types::CertificateDer::from(signed.server_certificate.as_slice());
    if Fingerprint::of(&certificate) != server {
        return Err(Invalid::OtherServer);
    }
    let key = ed25519_key(&signed.server_certificate).ok_or(Invalid::Malformed)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&signed_bytes(&signed.grant), &signed.signature)
        .map_err(|_| Invalid::Signature)?;
    Grant::from_bytes(&signed.grant).map_err(|_| Invalid::Malformed)
}

fn signed_bytes(grant: &[u8]) -> Vec<u8> {
    [SIGNING_CONTEXT, grant].concat()
}

/// The Ed25519 public key in a certificate. Only ever applied to the pinned
/// certificate — its hash was checked first — so finding the key's header is
/// enough; there is exactly one in the certificates `Identity` makes.
fn ed25519_key(certificate: &[u8]) -> Option<&[u8]> {
    let at = certificate
        .windows(ED25519_SPKI_PREFIX.len())
        .position(|window| window == ED25519_SPKI_PREFIX)?;
    certificate.get(at + ED25519_SPKI_PREFIX.len()..at + ED25519_SPKI_PREFIX.len() + 32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nearhand_core::grant::Role;

    fn grant() -> Grant {
        Grant {
            device: [7; 32],
            user: "ada".into(),
            role: Role::Control,
            issued_at: 1_000,
            expires_at: 1_300,
            nonce: [1; 16],
        }
    }

    #[test]
    fn a_signed_grant_checks_out_against_its_server_only() {
        let server = Identity::generate().expect("server");
        let signed = server.sign_grant(&grant()).expect("sign");
        assert_eq!(verify(&signed, server.fingerprint()), Ok(grant()));

        let other = Identity::generate().expect("other server");
        assert_eq!(
            verify(&signed, other.fingerprint()),
            Err(Invalid::OtherServer)
        );
        // Another server's certificate swapped in, with the key it pins.
        let mut swapped = signed.clone();
        swapped.server_certificate = other.cert.to_vec();
        assert_eq!(
            verify(&swapped, other.fingerprint()),
            Err(Invalid::Signature)
        );
    }

    #[test]
    fn a_changed_grant_or_signature_fails() {
        let server = Identity::generate().expect("server");
        let signed = server.sign_grant(&grant()).expect("sign");

        let mut promoted = grant();
        promoted.role = Role::Full;
        let mut forged = signed.clone();
        forged.grant = promoted.to_bytes().expect("encode");
        assert_eq!(
            verify(&forged, server.fingerprint()),
            Err(Invalid::Signature)
        );

        let mut scratched = signed.clone();
        scratched.signature[0] ^= 1;
        assert_eq!(
            verify(&scratched, server.fingerprint()),
            Err(Invalid::Signature)
        );
        scratched.signature.truncate(10);
        assert_eq!(
            verify(&scratched, server.fingerprint()),
            Err(Invalid::Signature)
        );
    }

    #[test]
    fn the_key_is_found_in_our_certificates() {
        let identity = Identity::generate().expect("identity");
        let key = ed25519_key(&identity.cert).expect("key");
        assert_eq!(key.len(), 32);
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(identity.key.secret_pkcs8_der())
            .expect("pair");
        use ring::signature::KeyPair;
        assert_eq!(key, pair.public_key().as_ref());
    }
}
