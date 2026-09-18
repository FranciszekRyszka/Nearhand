//! Clipboard text, kept in step between viewer and agent. One backend per OS.
//!
//! Backends: the Win32 clipboard on Windows; `NSPasteboard` on macOS [M4].
//!
//! Both sides run the same [`ClipboardSync`]: it polls the platform's change
//! counter a few times a second, which needs no window and costs nothing
//! measurable, and it remembers the last text that crossed in either direction
//! so a value it has just pasted is not sent straight back.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use nearhand_core::Clipboard;

#[cfg(windows)]
mod win32;

/// How often the clipboard is checked for a change. A copy followed by a
/// paste on the other machine takes longer than this.
const POLL: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no clipboard backend available on this platform")]
    Unsupported,
    #[error("clipboard backend failure: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Raw access to the platform clipboard. Text crosses this boundary with `\n`
/// line endings; backends convert to and from the platform's own.
pub trait Backend: Send {
    /// A number that changes whenever the clipboard's contents do.
    fn sequence(&mut self) -> u32;
    /// The clipboard's text, or `None` if it holds something else.
    fn text(&mut self) -> Result<Option<String>>;
    fn set_text(&mut self, text: &str) -> Result<()>;
}

/// The platform clipboard.
#[cfg(windows)]
pub fn open() -> Result<Box<dyn Backend>> {
    Ok(Box::new(win32::Win32Clipboard))
}

/// The platform clipboard.
#[cfg(not(windows))]
pub fn open() -> Result<Box<dyn Backend>> {
    Err(Error::Unsupported)
}

/// Keeps one side's clipboard in step with the other's, on a thread of its
/// own. Stops when dropped.
pub struct ClipboardSync {
    remote: mpsc::Sender<String>,
}

impl ClipboardSync {
    /// Start watching the platform clipboard. `on_change` gets each local
    /// change, never the contents at startup.
    pub fn start(on_change: impl FnMut(String) + Send + 'static) -> Result<Self> {
        Ok(Self::with_backend(open()?, on_change, POLL))
    }

    fn with_backend(
        backend: Box<dyn Backend>,
        on_change: impl FnMut(String) + Send + 'static,
        poll: Duration,
    ) -> Self {
        let (remote, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("clipboard".to_owned())
            .spawn(move || run(backend, rx, on_change, poll))
            .map(|_| ())
            .unwrap_or_else(|e| tracing::warn!(error = %e, "clipboard sync not started"));
        Self { remote }
    }

    /// Put text that arrived from the other side on the local clipboard.
    pub fn apply(&self, text: String) {
        // Fails only if the thread has gone, when there is nothing to do.
        let _ = self.remote.send(text);
    }
}

fn run(
    mut backend: Box<dyn Backend>,
    remote: mpsc::Receiver<String>,
    mut on_change: impl FnMut(String),
    poll: Duration,
) {
    let mut seen = backend.sequence();
    // The last text both sides are known to hold.
    let mut last: Option<String> = None;
    loop {
        match remote.recv_timeout(poll) {
            Ok(text) => {
                tracing::debug!(bytes = text.len(), "clipboard: pasting remote text");
                match backend.set_text(&text) {
                    // Our own write is not a local change.
                    Ok(()) => seen = backend.sequence(),
                    Err(e) => tracing::warn!(error = %e, "could not set the clipboard"),
                }
                last = Some(text);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }

        let now = backend.sequence();
        if now == seen {
            continue;
        }
        let text = match backend.text() {
            Ok(text) => text,
            // Usually another program holding the clipboard open; the next
            // poll tries again.
            Err(e) => {
                tracing::debug!(error = %e, "could not read the clipboard");
                continue;
            }
        };
        seen = now;
        let Some(text) = text else { continue };
        if last.as_ref() == Some(&text) {
            continue;
        }
        if text.len() > Clipboard::MAX_TEXT {
            tracing::info!(bytes = text.len(), "clipboard text too large to send");
            continue;
        }
        last = Some(text.clone());
        tracing::debug!(bytes = text.len(), "clipboard: sending local copy");
        on_change(text);
    }
}

/// `\r\n` to `\n`, for text leaving a Windows clipboard.
pub fn to_lf(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// `\n` to `\r\n`, for text entering a Windows clipboard. Existing `\r\n`
/// pairs are left alone.
pub fn to_crlf(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + text.len() / 32);
    let mut previous = '\0';
    for c in text.chars() {
        if c == '\n' && previous != '\r' {
            out.push('\r');
        }
        out.push(c);
        previous = c;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// A clipboard in memory, shared with the test so it can play the user.
    #[derive(Clone, Default)]
    struct Fake(Arc<Mutex<(u32, Option<String>)>>);

    impl Fake {
        fn copy(&self, text: &str) {
            let mut state = self.0.lock().expect("lock");
            state.0 += 1;
            state.1 = Some(text.to_owned());
        }

        fn contents(&self) -> Option<String> {
            self.0.lock().expect("lock").1.clone()
        }
    }

    impl Backend for Fake {
        fn sequence(&mut self) -> u32 {
            self.0.lock().expect("lock").0
        }
        fn text(&mut self) -> Result<Option<String>> {
            Ok(self.contents())
        }
        fn set_text(&mut self, text: &str) -> Result<()> {
            self.copy(text);
            Ok(())
        }
    }

    fn start(fake: &Fake) -> (ClipboardSync, Arc<Mutex<Vec<String>>>) {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let log = sent.clone();
        let sync = ClipboardSync::with_backend(
            Box::new(fake.clone()),
            move |text| log.lock().expect("lock").push(text),
            Duration::from_millis(5),
        );
        (sync, sent)
    }

    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn sends_local_copies_but_not_what_was_there_at_start() {
        let fake = Fake::default();
        fake.copy("before the session");
        let (_sync, sent) = start(&fake);
        std::thread::sleep(Duration::from_millis(30));
        fake.copy("during");
        wait_until("the copy to be sent", || {
            !sent.lock().expect("lock").is_empty()
        });
        assert_eq!(*sent.lock().expect("lock"), ["during"]);
    }

    #[test]
    fn remote_text_is_pasted_and_not_echoed_back() {
        let fake = Fake::default();
        let (sync, sent) = start(&fake);
        sync.apply("from the other side".to_owned());
        wait_until("the paste", || {
            fake.contents().as_deref() == Some("from the other side")
        });
        // Something else rewriting the same text, as clipboard managers do.
        fake.copy("from the other side");
        std::thread::sleep(Duration::from_millis(40));
        assert!(sent.lock().expect("lock").is_empty());
        fake.copy("a new local copy");
        wait_until("the new copy", || sent.lock().expect("lock").len() == 1);
    }

    #[test]
    fn oversized_text_stays_local() {
        let fake = Fake::default();
        let (_sync, sent) = start(&fake);
        fake.copy(&"x".repeat(Clipboard::MAX_TEXT + 1));
        std::thread::sleep(Duration::from_millis(40));
        fake.copy("small");
        wait_until("the small copy", || !sent.lock().expect("lock").is_empty());
        assert_eq!(*sent.lock().expect("lock"), ["small"]);
    }

    #[test]
    fn line_endings_convert_both_ways() {
        assert_eq!(to_lf("a\r\nb\nc\r\n"), "a\nb\nc\n");
        assert_eq!(to_crlf("a\nb\r\nc"), "a\r\nb\r\nc");
        assert_eq!(to_lf(&to_crlf("x\n\ny")), "x\n\ny");
    }
}
