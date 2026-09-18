//! The viewer's keyboard and mouse, applied to this machine.
//!
//! Injection runs on a thread of its own rather than on the runtime: which
//! desktop input lands on is a property of the calling thread on Windows, and
//! the M3 service will have to switch that thread between the user's desktop,
//! UAC and the login screen without disturbing anything else.

use std::sync::mpsc;

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

fn run(mut injector: Box<dyn nearhand_input::Injector>, commands: mpsc::Receiver<Command>) {
    let mut warned = false;
    for command in commands {
        match command {
            Command::Retarget(target) => injector.set_target(target),
            Command::Inject(event) => {
                if let Err(e) = injector.inject(&event) {
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
