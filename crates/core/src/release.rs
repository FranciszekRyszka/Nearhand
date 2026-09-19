//! Releases: what an agent may update itself to.
//!
//! Each package the project builds — for now the Windows agent's MSI — comes
//! with a [`SignedRelease`]: what the package is, its hash, and a signature
//! by the project's release key. Every agent carries that key's public half
//! ([`KEY`]) and installs nothing it does not verify, whatever server
//! offers it: a server can choose *when* its agents update, and to which of
//! the project's releases, but it cannot make them run anything else.
//!
//! The signature covers [`SIGNING_CONTEXT`] followed by `release`, the
//! postcard encoding of a [`Release`], exactly as sent. Signing and checking
//! are in `nearhand_transport::release`; `nearhand-release` is the tool.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Put before the signed bytes, so a release signature can never be taken
/// for a signature over anything else.
pub const SIGNING_CONTEXT: &[u8] = b"nearhand release v1\0";

/// The project's release key: the Ed25519 public key agents check releases
/// against. Its private half is the `NEARHAND_RELEASE_KEY` secret of the
/// repository's CI, which signs the packages it builds, and is nowhere else.
pub const KEY: [u8; 32] = [
    0x19, 0x9c, 0xb3, 0xec, 0x8a, 0x48, 0x64, 0x62, //
    0x7e, 0x1c, 0x28, 0xec, 0x72, 0xb0, 0x54, 0xf8, //
    0x69, 0x0f, 0xea, 0x60, 0xe2, 0x86, 0x64, 0xdb, //
    0x84, 0x60, 0xbc, 0xec, 0xcb, 0xa1, 0xbe, 0x12,
];

/// The product an agent updates.
pub const AGENT: &str = "nearhand-agent";

/// The platform a package is for, as releases name it.
pub const WINDOWS_X86_64: &str = "windows-x86_64";

/// How a package installs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Package {
    /// A Windows Installer package, installed over the one there.
    Msi,
}

/// What the release key vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Release {
    /// [`AGENT`], for now.
    pub product: String,
    pub version: Version,
    /// [`WINDOWS_X86_64`], for now.
    pub platform: String,
    pub package: Package,
    /// SHA-256 of the package file.
    pub sha256: [u8; 32],
    /// The package file's size in bytes.
    pub size: u64,
}

impl Release {
    /// The encoding that is signed.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::Error> {
        postcard::to_stdvec(self).map_err(crate::Error::Encode)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        postcard::from_bytes(bytes).map_err(crate::Error::Decode)
    }
}

/// A release and the release key's signature over it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelease {
    /// The postcard encoding of a [`Release`], as signed.
    pub release: Vec<u8>,
    /// Ed25519, over [`SIGNING_CONTEXT`] then `release`.
    pub signature: Vec<u8>,
}

impl SignedRelease {
    /// What the release says, unchecked: for showing it. Anything that acts
    /// on it checks the signature first.
    pub fn claims(&self) -> Result<Release, crate::Error> {
        Release::from_bytes(&self.release)
    }

    /// The signature file that goes beside a package: two lines of hex,
    /// `release …` and `signature …`, readable by anything without a
    /// library.
    pub fn to_text(&self) -> String {
        format!(
            "release {}\nsignature {}\n",
            hex(&self.release),
            hex(&self.signature)
        )
    }

    pub fn from_text(text: &str) -> Result<Self, String> {
        let mut release = None;
        let mut signature = None;
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let (name, value) = line
                .split_once(' ')
                .ok_or_else(|| format!("not a signature file line: {line:?}"))?;
            let field = match name {
                "release" => &mut release,
                "signature" => &mut signature,
                other => return Err(format!("unknown field {other:?} in the signature file")),
            };
            if field.replace(unhex(value.trim())?).is_some() {
                return Err(format!("{name} twice in the signature file"));
            }
        }
        match (release, signature) {
            (Some(release), Some(signature)) => Ok(Self { release, signature }),
            _ => Err("the signature file needs a release and a signature line".to_owned()),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex".to_owned());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("not hex: {text:?}"))
        })
        .collect()
}

impl fmt::Debug for SignedRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.claims() {
            Ok(release) => write!(f, "SignedRelease({release:?})"),
            Err(_) => f.write_str("SignedRelease(undecodable)"),
        }
    }
}

/// `major.minor.patch`, ordered as numbers: 0.10.0 comes after 0.9.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || format!("{s:?} is not a version: major.minor.patch");
        let mut parts = s.split('.').map(|part| {
            // Digits only: no signs, no spaces, no pre-release suffixes.
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            part.parse::<u32>().map_err(|_| bad())
        });
        let (Some(major), Some(minor), Some(patch), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        Ok(Self {
            major: major?,
            minor: minor?,
            patch: patch?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(s: &str) -> Version {
        s.parse().expect("version")
    }

    #[test]
    fn versions_parse_and_order_as_numbers() {
        assert_eq!(
            version("1.20.3"),
            Version {
                major: 1,
                minor: 20,
                patch: 3
            }
        );
        assert_eq!(version("0.10.0").to_string(), "0.10.0");
        assert!(version("0.10.0") > version("0.9.3"));
        assert!(version("1.0.0") > version("0.99.99"));
        assert!(version("0.1.1") > version("0.1.0"));
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "1.2.x",
            "1.-2.3",
            "1.2.3-rc1",
            " 1.2.3",
            "1..3",
        ] {
            assert!(bad.parse::<Version>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn claims_read_back() {
        let release = Release {
            product: AGENT.into(),
            version: version("0.2.0"),
            platform: WINDOWS_X86_64.into(),
            package: Package::Msi,
            sha256: [5; 32],
            size: 6_000_000,
        };
        let signed = SignedRelease {
            release: release.to_bytes().expect("encode"),
            signature: vec![0; 64],
        };
        assert_eq!(signed.claims().expect("claims"), release);
        let bytes = postcard::to_stdvec(&signed).expect("encode");
        let back: SignedRelease = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, signed);
        assert_eq!(
            SignedRelease::from_text(&signed.to_text()).expect("text"),
            signed
        );
    }

    #[test]
    fn signature_files_are_strict() {
        let good = "release 0a0b\nsignature ff\n";
        let read = SignedRelease::from_text(good).expect("read");
        assert_eq!((read.release, read.signature), (vec![10, 11], vec![255]));
        for bad in [
            "release 0a0b\n",
            "release 0a0b\nsignature ff\nsignature ff\n",
            "release 0a0\nsignature ff\n",
            "release 0g0b\nsignature ff\n",
            "release 0a0b\nsignature ff\nextra 00\n",
            "release\nsignature ff\n",
            "release é1\nsignature ff\n",
        ] {
            assert!(SignedRelease::from_text(bad).is_err(), "{bad:?}");
        }
    }
}
