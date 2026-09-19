//! Signing releases, and checking them and their packages
//! (`nearhand_core::release`).
//!
//! The release key is a plain Ed25519 key pair, separate from every server
//! and device key: it is the project's, it signs in CI, and agents check
//! against its public half built into them.

use nearhand_core::release::{Release, SIGNING_CONTEXT, SignedRelease};
use ring::digest::{Context, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::{Error, Result};

/// A new release key: its private half as PKCS#8, to keep secret, and its
/// public half, to build into agents.
pub fn generate_key() -> Result<(Vec<u8>, [u8; 32])> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| Error::Config("could not generate a key".to_owned()))?;
    let public = public_key(pkcs8.as_ref())?;
    Ok((pkcs8.as_ref().to_vec(), public))
}

/// The public half of the release key `pkcs8`.
pub fn public_key(pkcs8: &[u8]) -> Result<[u8; 32]> {
    let pair = key_pair(pkcs8)?;
    pair.public_key()
        .as_ref()
        .try_into()
        .map_err(|_| Error::Config("not an Ed25519 key".to_owned()))
}

/// Sign `release` with the release key `pkcs8`.
pub fn sign(pkcs8: &[u8], release: &Release) -> Result<SignedRelease> {
    let pair = key_pair(pkcs8)?;
    let release = release.to_bytes()?;
    let signature = pair.sign(&signed_bytes(&release)).as_ref().to_vec();
    Ok(SignedRelease { release, signature })
}

fn key_pair(pkcs8: &[u8]) -> Result<Ed25519KeyPair> {
    Ed25519KeyPair::from_pkcs8_maybe_unchecked(pkcs8)
        .map_err(|e| Error::Config(format!("not an Ed25519 release key: {e}")))
}

/// Why a release or its package was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    #[error("the release is not signed by the release key")]
    Signature,
    #[error("the release cannot be read")]
    Malformed,
    #[error("the package is not the one the release describes")]
    Package,
}

/// What `signed` says, if the release key whose public half is `key`
/// signed it.
pub fn verify(signed: &SignedRelease, key: &[u8; 32]) -> std::result::Result<Release, Invalid> {
    UnparsedPublicKey::new(&ED25519, key)
        .verify(&signed_bytes(&signed.release), &signed.signature)
        .map_err(|_| Invalid::Signature)?;
    Release::from_bytes(&signed.release).map_err(|_| Invalid::Malformed)
}

/// Whether `package` is the file `release` describes: its size, then its
/// hash.
pub fn check_package(release: &Release, package: &[u8]) -> std::result::Result<(), Invalid> {
    if package.len() as u64 != release.size || sha256(package) != release.sha256 {
        return Err(Invalid::Package);
    }
    Ok(())
}

/// SHA-256 of `data`, as a release records it.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut context = Context::new(&SHA256);
    context.update(data);
    let mut hash = [0; 32];
    hash.copy_from_slice(context.finish().as_ref());
    hash
}

fn signed_bytes(release: &[u8]) -> Vec<u8> {
    [SIGNING_CONTEXT, release].concat()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nearhand_core::release::{AGENT, Package, WINDOWS_X86_64};

    fn release(package: &[u8]) -> Release {
        Release {
            product: AGENT.into(),
            version: "0.2.0".parse().expect("version"),
            platform: WINDOWS_X86_64.into(),
            package: Package::Msi,
            sha256: sha256(package),
            size: package.len() as u64,
        }
    }

    #[test]
    fn a_signed_release_checks_out_against_its_key_only() {
        let (private, public) = generate_key().expect("key");
        assert_eq!(public_key(&private).expect("public"), public);
        let signed = sign(&private, &release(b"package")).expect("sign");
        assert_eq!(verify(&signed, &public), Ok(release(b"package")));

        let (_, other) = generate_key().expect("other key");
        assert_eq!(verify(&signed, &other), Err(Invalid::Signature));
    }

    #[test]
    fn a_changed_release_or_signature_fails() {
        let (private, public) = generate_key().expect("key");
        let signed = sign(&private, &release(b"package")).expect("sign");

        let mut newer = release(b"package");
        newer.version = "9.0.0".parse().expect("version");
        let mut forged = signed.clone();
        forged.release = newer.to_bytes().expect("encode");
        assert_eq!(verify(&forged, &public), Err(Invalid::Signature));

        let mut garbled = signed.clone();
        garbled.signature[0] ^= 1;
        assert_eq!(verify(&garbled, &public), Err(Invalid::Signature));

        // A signature over the bare release, without the context, is not
        // one over the release.
        let pair = key_pair(&private).expect("pair");
        let mut bare = signed;
        bare.signature = pair.sign(&bare.release).as_ref().to_vec();
        assert_eq!(verify(&bare, &public), Err(Invalid::Signature));
    }

    #[test]
    fn only_the_described_package_passes() {
        let release = release(b"the package");
        assert_eq!(check_package(&release, b"the package"), Ok(()));
        assert_eq!(
            check_package(&release, b"the packagE"),
            Err(Invalid::Package)
        );
        assert_eq!(
            check_package(&release, b"the package, longer"),
            Err(Invalid::Package)
        );
    }
}
