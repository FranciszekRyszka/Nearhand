//! The log file, kept to a size: past its limit it becomes `<name>.1` —
//! replacing the one before — and a new one starts. An installed agent runs
//! for months without restarting, so a check only at start would let it
//! grow without end; starting over instead of keeping `.1` would lose what
//! led up to a problem just when someone comes looking.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// A log file that turns over at `limit` bytes.
pub struct Rotating {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    limit: u64,
}

impl Rotating {
    pub fn open(path: &Path, limit: u64) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let file = append(path).with_context(|| format!("opening {}", path.display()))?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            file: Some(file),
            written,
            limit,
        })
    }

    /// Where the log before this one is kept.
    pub fn previous(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(".1");
        PathBuf::from(name)
    }

    /// Close this file, move it aside, and start another. Windows renames
    /// no file that is open, so it is closed first. If it cannot be moved —
    /// someone has it open without sharing — the same file goes on, and the
    /// next limit tries again: lines are not thrown away for want of a
    /// rename.
    fn turn_over(&mut self) {
        self.file = None;
        let _ = std::fs::rename(&self.path, Self::previous(&self.path));
        self.file = append(&self.path).ok();
        self.written = 0;
    }
}

fn append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

impl Write for Rotating {
    /// One event is one write, so an event is never split between files.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written > 0 && self.written + buf.len() as u64 > self.limit {
            self.turn_over();
        }
        if self.file.is_none() {
            self.file = append(&self.path).ok();
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("the log file could not be opened"))?;
        let n = file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), File::flush)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nearhand-log-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("logs").join("agent.log")
    }

    fn read(path: &Path) -> String {
        std::fs::read_to_string(path).unwrap_or_default()
    }

    #[test]
    fn a_full_log_moves_aside_whole_lines_and_all() {
        let path = scratch("turn");
        let mut log = Rotating::open(&path, 100).expect("open");
        for i in 0..12 {
            log.write_all(format!("line {i:02} of the log\n").as_bytes())
                .expect("write");
        }
        drop(log);
        let now = read(&path);
        let before = read(&Rotating::previous(&path));
        assert!(
            now.len() <= 100 && before.len() <= 100,
            "{now:?} / {before:?}"
        );
        assert!(now.ends_with("line 11 of the log\n"), "{now:?}");
        // The two files hold the most recent lines, in order, none cut.
        let joined = format!("{before}{now}");
        let lines: Vec<&str> = joined.lines().collect();
        assert!(lines.iter().all(|l| l.len() == "line 00 of the log".len()));
        let last: Vec<u32> = lines.iter().map(|l| l[5..7].parse().expect("n")).collect();
        assert!(last.windows(2).all(|w| w[1] == w[0] + 1), "{last:?}");
        assert_eq!(*last.last().expect("some"), 11);
        let _ = std::fs::remove_dir_all(path.parent().and_then(Path::parent).expect("dir"));
    }

    #[test]
    fn a_reopened_log_keeps_counting_from_its_size() {
        let path = scratch("reopen");
        {
            let mut log = Rotating::open(&path, 1000).expect("open");
            log.write_all(&[b'a'; 900]).expect("write");
        }
        let mut log = Rotating::open(&path, 1000).expect("open again");
        log.write_all(&[b'b'; 200]).expect("write");
        drop(log);
        assert_eq!(
            read(&Rotating::previous(&path)).len(),
            900,
            "moved aside, not wiped"
        );
        assert_eq!(read(&path).len(), 200);
        let _ = std::fs::remove_dir_all(path.parent().and_then(Path::parent).expect("dir"));
    }

    #[test]
    fn one_event_over_the_limit_still_goes_in() {
        let path = scratch("big");
        let mut log = Rotating::open(&path, 10).expect("open");
        log.write_all(&[b'x'; 50]).expect("write");
        drop(log);
        assert_eq!(read(&path).len(), 50);
        assert!(
            !Rotating::previous(&path).exists(),
            "an empty file is not moved aside"
        );
        let _ = std::fs::remove_dir_all(path.parent().and_then(Path::parent).expect("dir"));
    }
}
