//! Device keys this viewer has seen before.
//!
//! A server tells a viewer which key a device has. A device's ID is made
//! from that key — the first bytes of its fingerprint — so a server cannot
//! simply answer with any key it likes; but ten digits are not many, and a
//! server willing to grind keys can find one whose ID matches
//! (`docs/security.md`).
//!
//! So the viewer remembers. The first time it reaches a device it writes
//! the whole fingerprint down; every time after, the key must be the same
//! one. A device that is reinstalled with a new key gets a new ID with it,
//! so the same ID with another key is not a reinstall — it is another key,
//! and the session stops until the person says otherwise.
//!
//! This matters most for a session opened with a grant, where no password
//! is proved and the server's word is otherwise all there is.
//!
//! The file is a line per device: the ten digits, a space, the fingerprint
//! in hex. Comments start with `#`. It is a viewer's own note, not a
//! secret: losing it costs one "seen for the first time" per device.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nearhand_core::rendezvous::DeviceId;
use nearhand_transport::Fingerprint;

/// What the store makes of a key offered for an ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuity {
    /// Never seen this device before.
    First,
    /// The key it had last time.
    Same,
    /// Another key under the same ID.
    Changed { known: Fingerprint },
}

#[derive(Debug, Default)]
pub struct Known {
    path: Option<PathBuf>,
    devices: BTreeMap<u64, Fingerprint>,
}

impl Known {
    /// The store for this user, or an empty one that remembers nothing if
    /// there is nowhere to keep it.
    pub fn load() -> Self {
        let Some(path) = path() else {
            tracing::warn!("no home folder: device keys will not be remembered");
            return Self::default();
        };
        match Self::read(&path) {
            Ok(known) => known,
            Err(e) => {
                // A file that cannot be read is not a reason to refuse to
                // connect; it is a reason to say so and start again.
                tracing::warn!(path = %path.display(), error = %format!("{e:#}"), "cannot read the known devices");
                Self {
                    path: Some(path),
                    devices: BTreeMap::new(),
                }
            }
        }
    }

    fn read(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path: Some(path.to_path_buf()),
            devices: parse(&text),
        })
    }

    /// Whether `fingerprint` is the key this device had before.
    pub fn check(&self, id: DeviceId, fingerprint: Fingerprint) -> Continuity {
        match self.devices.get(&id.value()) {
            None => Continuity::First,
            Some(known) if *known == fingerprint => Continuity::Same,
            Some(known) => Continuity::Changed { known: *known },
        }
    }

    /// Write this key down as the device's, replacing what was there.
    pub fn remember(&mut self, id: DeviceId, fingerprint: Fingerprint) -> Result<()> {
        if self.devices.insert(id.value(), fingerprint) == Some(fingerprint) {
            return Ok(());
        }
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        // Written aside and renamed, so an interrupted write cannot leave
        // half a file behind.
        let partial = path.with_extension("partial");
        std::fs::write(&partial, self.to_text())
            .with_context(|| format!("writing {}", partial.display()))?;
        std::fs::rename(&partial, &path).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    fn to_text(&self) -> String {
        let mut out = String::from(
            "# Device keys this viewer has seen. A device's ID is made from its\n\
             # key, so the same ID with another key is another device.\n\
             # Written by nearhand-viewer; delete a line to forget a device.\n",
        );
        for (id, fingerprint) in &self.devices {
            out.push_str(&format!("{id:010} {fingerprint}\n"));
        }
        out
    }
}

fn parse(text: &str) -> BTreeMap<u64, Fingerprint> {
    let mut devices = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((id, fingerprint)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let (Ok(id), Ok(fingerprint)) = (id.trim().parse::<u64>(), fingerprint.trim().parse())
        else {
            // A line that cannot be read is skipped rather than fatal: the
            // worst it costs is one device seen for the first time again.
            continue;
        };
        devices.insert(id, fingerprint);
    }
    devices
}

/// Where the file lives: with this user's data, not the machine's, because
/// what one person has seen is not what another has.
fn path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Application Support"))
    } else {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
    };
    Some(base?.join("Nearhand").join("known-devices"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(byte: u8) -> Fingerprint {
        Fingerprint::from_bytes([byte; 32])
    }

    fn id(value: u64) -> DeviceId {
        format!("{value:010}").parse().expect("a ten-digit id")
    }

    #[test]
    fn a_device_is_new_once_and_the_same_after() {
        let mut known = Known::default();
        assert_eq!(known.check(id(1), fingerprint(7)), Continuity::First);
        known
            .remember(id(1), fingerprint(7))
            .expect("no file to write");
        assert_eq!(known.check(id(1), fingerprint(7)), Continuity::Same);
        assert_eq!(
            known.check(id(1), fingerprint(8)),
            Continuity::Changed {
                known: fingerprint(7)
            }
        );
        // Another device is its own story.
        assert_eq!(known.check(id(2), fingerprint(7)), Continuity::First);
    }

    #[test]
    fn what_is_written_reads_back() {
        let mut known = Known::default();
        known
            .remember(id(1_234_567_890), fingerprint(3))
            .expect("remember");
        known.remember(id(42), fingerprint(4)).expect("remember");
        let text = known.to_text();
        assert!(text.contains("1234567890 "), "{text}");
        // Ten digits, leading zeros and all, as a device shows its ID.
        assert!(text.contains("\n0000000042 "), "{text}");
        assert_eq!(parse(&text), known.devices);
    }

    #[test]
    fn lines_that_make_no_sense_are_skipped_not_fatal() {
        let text = "# a comment\n\nnonsense\n12 not-a-fingerprint\n0000000007 ".to_owned()
            + &fingerprint(9).to_string()
            + "\n";
        let devices = parse(&text);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices.get(&7), Some(&fingerprint(9)));
    }
}
