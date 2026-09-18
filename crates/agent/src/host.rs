//! The person at this machine: what the portable agent tells them, and what
//! they decide.
//!
//! Sessions ask here before they start and report here while they run; the
//! quick-support window shows it all and answers. Without a window — the
//! agent run from a terminal — no one is asked, the password alone lets a
//! viewer in, and sessions are announced on the terminal instead.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// How long the person at the host has to allow a session before it counts
/// as refused.
pub const ASK_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Host {
    /// Whether someone answers: a window is showing.
    interactive: bool,
    state: Mutex<State>,
    /// Called on every change, so a window can redraw.
    notify: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

#[derive(Default)]
struct State {
    server: Server,
    request: Option<Request>,
    session: Option<Session>,
    next: u64,
}

/// Where the registration with the server stands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Server {
    #[default]
    Connecting,
    /// Registered: viewers can find this device.
    Online,
    /// Not registered; `error` says why.
    Unreachable { error: String },
}

struct Request {
    number: u64,
    viewer: String,
    deadline: Instant,
    answer: oneshot::Sender<bool>,
}

struct Session {
    number: u64,
    viewer: String,
    since: Instant,
    /// Ends it, from this side.
    end: Box<dyn Fn() + Send + Sync>,
}

/// What there is to show, at one moment.
#[derive(Debug, Clone, Default)]
pub struct View {
    pub server: Server,
    /// A viewer waiting to be allowed in, and the time left to answer.
    pub request: Option<(String, Duration)>,
    /// The viewer in session, and for how long.
    pub session: Option<(String, Duration)>,
}

impl Host {
    pub fn new(interactive: bool) -> Arc<Self> {
        Arc::new(Self {
            interactive,
            state: Mutex::default(),
            notify: Mutex::default(),
        })
    }

    /// Have `notify` called whenever there is something new to show.
    pub fn on_change(&self, notify: impl Fn() + Send + Sync + 'static) {
        *self.notify.lock().unwrap_or_else(|p| p.into_inner()) = Some(Box::new(notify));
    }

    /// Whether sessions wait for someone to answer [`Host::ask`].
    pub fn asks(&self) -> bool {
        self.interactive
    }

    pub fn view(&self) -> View {
        let now = Instant::now();
        let state = self.lock();
        View {
            server: state.server.clone(),
            request: state
                .request
                .as_ref()
                .map(|r| (r.viewer.clone(), r.deadline.saturating_duration_since(now))),
            session: state
                .session
                .as_ref()
                .map(|s| (s.viewer.clone(), now.duration_since(s.since))),
        }
    }

    pub fn set_server(&self, server: Server) {
        {
            let mut state = self.lock();
            if state.server == server {
                return;
            }
            state.server = server;
        }
        self.changed();
    }

    /// Whether the person at the host allows `viewer` in. Refused if they do
    /// not answer within [`ASK_TIMEOUT`], or if the viewer leaves first —
    /// `gone` completes. With no window, allowed: the password was the check.
    pub async fn ask(&self, viewer: &str, gone: impl Future<Output = ()>) -> bool {
        if !self.interactive {
            return true;
        }
        let (answer, answered) = oneshot::channel();
        let number = {
            let mut state = self.lock();
            state.next += 1;
            // Sessions take turns (one viewer at a time), so this replaces
            // nothing still waiting; a leftover is refused by being dropped.
            state.request = Some(Request {
                number: state.next,
                viewer: viewer.to_owned(),
                deadline: Instant::now() + ASK_TIMEOUT,
                answer,
            });
            state.next
        };
        self.changed();
        let allowed = tokio::select! {
            answer = answered => answer.unwrap_or(false),
            () = tokio::time::sleep(ASK_TIMEOUT) => false,
            () = gone => false,
        };
        {
            let mut state = self.lock();
            if state.request.as_ref().is_some_and(|r| r.number == number) {
                state.request = None;
            }
        }
        self.changed();
        allowed
    }

    /// The person at the host answers the waiting request.
    pub fn answer(&self, allow: bool) {
        let request = self.lock().request.take();
        if let Some(request) = request {
            let _ = request.answer.send(allow);
        }
        self.changed();
    }

    /// A session with `viewer` has started; it is shown until the returned
    /// guard is dropped. `end` ends it, if the person at the host asks to.
    pub fn session_started(
        self: &Arc<Self>,
        viewer: &str,
        end: impl Fn() + Send + Sync + 'static,
    ) -> InSession {
        let number = {
            let mut state = self.lock();
            state.next += 1;
            state.session = Some(Session {
                number: state.next,
                viewer: viewer.to_owned(),
                since: Instant::now(),
                end: Box::new(end),
            });
            state.next
        };
        if !self.interactive {
            // Printed rather than logged: this is the session indicator.
            println!("session started: {viewer}");
        }
        self.changed();
        InSession {
            host: self.clone(),
            number,
        }
    }

    /// The person at the host ends the session.
    pub fn end_session(&self) {
        if let Some(session) = &self.lock().session {
            (session.end)();
        }
    }

    fn changed(&self) {
        if let Some(notify) = &*self.notify.lock().unwrap_or_else(|p| p.into_inner()) {
            notify();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// A session being shown to the person at the host.
pub struct InSession {
    host: Arc<Host>,
    number: u64,
}

impl Drop for InSession {
    fn drop(&mut self) {
        let ended = {
            let mut state = self.host.lock();
            let ours = state
                .session
                .as_ref()
                .is_some_and(|s| s.number == self.number);
            ours.then(|| state.session.take()).flatten()
        };
        if let Some(session) = ended {
            if !self.host.interactive {
                println!("session ended: {}", session.viewer);
            }
            self.host.changed();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;

    /// A host with a window, and a count of how often it was told to redraw.
    fn window() -> (Arc<Host>, Arc<AtomicUsize>) {
        let host = Host::new(true);
        let redraws = Arc::new(AtomicUsize::new(0));
        let count = redraws.clone();
        host.on_change(move || {
            count.fetch_add(1, Ordering::Relaxed);
        });
        (host, redraws)
    }

    async fn asked(host: &Host) {
        while host.view().request.is_none() {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn the_person_at_the_host_decides() {
        for allow in [true, false] {
            let (host, redraws) = window();
            let asking = {
                let host = host.clone();
                tokio::spawn(async move { host.ask("a viewer", std::future::pending()).await })
            };
            asked(&host).await;
            assert_eq!(host.view().request.expect("request").0, "a viewer");
            host.answer(allow);
            assert_eq!(asking.await.expect("ask"), allow);
            assert!(host.view().request.is_none(), "the question goes away");
            assert!(redraws.load(Ordering::Relaxed) >= 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn no_answer_is_no() {
        let (host, _) = window();
        assert!(!host.ask("a viewer", std::future::pending()).await);
        assert!(host.view().request.is_none());
    }

    #[tokio::test]
    async fn a_viewer_who_leaves_is_not_asked_about() {
        let (host, _) = window();
        assert!(!host.ask("a viewer", async {}).await);
        assert!(host.view().request.is_none());
    }

    #[tokio::test]
    async fn without_a_window_the_password_is_enough() {
        let host = Host::new(false);
        assert!(host.ask("a viewer", std::future::pending()).await);
    }

    #[test]
    fn sessions_show_until_they_end_and_can_be_ended_from_here() {
        let (host, _) = window();
        let ended = Arc::new(AtomicBool::new(false));
        let flag = ended.clone();
        let session = host.session_started("a viewer", move || flag.store(true, Ordering::Relaxed));
        assert_eq!(host.view().session.expect("session").0, "a viewer");

        host.end_session();
        assert!(ended.load(Ordering::Relaxed));
        drop(session);
        assert!(host.view().session.is_none());
    }
}
