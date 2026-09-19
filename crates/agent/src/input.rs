//! The viewer's keyboard and mouse, applied to this machine.
//!
//! Injection runs on a thread of its own rather than on the runtime: which
//! desktop input lands on is a property of the calling thread on Windows. The
//! thread follows the desktop receiving input — the user's, or the secure one
//! of the sign-in screen and UAC prompts — checking before input goes out,
//! and again when input is refused. Only SYSTEM may follow onto the secure
//! desktop; the portable agent's input is refused there, as before.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nearhand_core::Input;
use nearhand_input::Target;

enum Command {
    Inject(Input),
    Retarget(Target),
}

/// Feeds the injection thread. Clone one per stream reader.
///
/// The thread releases every key and button the viewer still holds, then
/// ends, once the last sender is dropped — at the latest when the session's
/// streams close with the connection.
#[derive(Clone)]
pub struct Injection(mpsc::Sender<Command>);

impl Injection {
    pub fn start(target: Target) -> Result<Self> {
        let injector = nearhand_input::open(target).context("opening the input injector")?;
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("input".to_owned())
            .spawn(move || run(injector, rx))
            .context("starting the input thread")?;
        Ok(Self(tx))
    }

    pub fn inject(&self, event: Input) {
        self.send(Command::Inject(event));
    }

    /// Point normalised coordinates at the monitor now being watched.
    pub fn retarget(&self, target: Target) {
        self.send(Command::Retarget(target));
    }

    fn send(&self, command: Command) {
        // Fails only once the thread has gone, when there is nothing left to
        // do with the event anyway.
        let _ = self.0.send(command);
    }
}

/// How often the input thread checks which desktop receives input, at most.
/// Each check is a couple of system calls; input comes much faster.
const DESKTOP_CHECK: Duration = Duration::from_millis(100);

fn run(mut injector: Box<dyn nearhand_input::Injector>, commands: mpsc::Receiver<Command>) {
    let mut warned = false;
    let mut desktop = Desktop::new();
    for command in commands {
        match command {
            Command::Retarget(target) => injector.set_target(target),
            Command::Inject(event) => {
                desktop.follow(false);
                let mut result = injector.inject(&event);
                // Refused: perhaps the desktop changed since the last check.
                if result.is_err() && desktop.follow(true) {
                    result = injector.inject(&event);
                }
                if let Err(e) = result {
                    // Typically an elevated window in the foreground, which a
                    // non-elevated agent may not touch. Worth one warning, not
                    // one per mouse move.
                    if warned {
                        tracing::debug!(error = %e, ?event, "input not injected");
                    } else {
                        tracing::warn!(error = %e, ?event, "input not injected");
                        warned = true;
                    }
                }
            }
        }
    }
    if let Err(e) = injector.release_all() {
        tracing::warn!(error = %e, "could not release held keys");
    }
}

/// The desktop the input thread is on, kept on the input desktop.
struct Desktop {
    #[cfg(windows)]
    thread: nearhand_capture::desktop::ThreadDesktop,
    checked: Option<Instant>,
}

impl Desktop {
    fn new() -> Self {
        Self {
            #[cfg(windows)]
            thread: nearhand_capture::desktop::ThreadDesktop::current(),
            checked: None,
        }
    }

    /// Move to the input desktop if it changed; `now` skips the rate limit.
    /// True when the thread moved.
    fn follow(&mut self, now: bool) -> bool {
        if !now && self.checked.is_some_and(|at| at.elapsed() < DESKTOP_CHECK) {
            return false;
        }
        self.checked = Some(Instant::now());
        #[cfg(windows)]
        match self.thread.follow() {
            Ok(moved) => moved,
            Err(e) => {
                tracing::debug!(error = %e, "input stays on the {} desktop", self.thread.name());
                false
            }
        }
        #[cfg(not(windows))]
        false
    }
}
