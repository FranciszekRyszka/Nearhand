//! One viewer, from handshake to goodbye.
//!
//! The viewer opens a bidirectional control stream and speaks first:
//!
//! ```text
//! viewer                         agent
//!   Hello { version, caps }  ──▶
//!                            ◀──  Hello { version, caps }
//!                            ◀──  MonitorList
//!   StartVideo               ──▶
//!                            ◀══  video datagrams …
//!   RequestKeyframe / SetQuality / StartVideo (another monitor) / Bye
//! ```
//!
//! Keyboard and mouse arrive on a unidirectional stream of their own, opened
//! by the viewer whenever it likes and tagged [`StreamKind::Input`]. The
//! pointer's shape and visibility go the other way, on one tagged
//! [`StreamKind::Cursor`] that lasts the whole session. Clipboard text goes
//! both ways, on a [`StreamKind::Clipboard`] stream in each direction.
//!
//! A protocol violation closes the connection with a code from
//! [`nearhand_core::proto::close`] and a reason the viewer can show.
//!
//! An agent that wants proof answers `Hello` with `AuthRequired` first: the
//! viewer gives a password, or presents a grant from the agent's server
//! (`grants`). A grant's role limits the session: with `view`, the viewer's
//! keyboard, mouse and clipboard are not taken, and this machine's
//! clipboard is not sent.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use nearhand_clipboard::ClipboardSync;
use nearhand_core::access;
use nearhand_core::grant::Role;
use nearhand_core::proto::close;
use nearhand_core::video::{encode_chunk, packetize};
use nearhand_core::{
    Caps, Clipboard, Control, Cursor, Input, Monitor, PROTOCOL_VERSION, StreamKind,
};
use nearhand_transport::rendezvous::{Path, path_of};
use nearhand_transport::{recv_message, send_all, send_message};
use quinn::{Connection, RecvStream};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::gate::Verdict;
use crate::grants::Grants;
use crate::host::{Host, InSession};
use crate::input::Injection;
use crate::pipeline::{Pipeline, QualityControl, Settings};
use crate::rate::{self, Quality, RateController};

/// Highest frame rate a viewer may ask for.
const MAX_FPS: u8 = 120;

/// How much recently sent video is kept for [`Control::Nack`]: about a second
/// at 60 fps, and never more memory than this. A repair older than that would
/// arrive too late to show anyway.
const SENT_FRAMES: usize = 64;
const SENT_BYTES: usize = 16 * 1024 * 1024;

/// How often a backlogged sender looks again. Short against a frame interval,
/// long against the cost of asking.
const BACKLOG_POLL: Duration = Duration::from_millis(2);

/// Starting video again after it stopped by itself: from this, doubling,
/// up to the max. Video that ran this long was fine, and the next restart
/// is prompt again.
const RESTART_FIRST: Duration = Duration::from_secs(1);
const RESTART_MAX: Duration = Duration::from_secs(30);
const HEALTHY_RUN: Duration = Duration::from_secs(30);

/// Stream priorities, highest first. Clipboard text can be large and must
/// never hold up the pointer.
const CURSOR_PRIORITY: i32 = 0;
const CLIPBOARD_PRIORITY: i32 = -1;

pub struct SessionConfig {
    /// The most video bitrate to use; rate control picks what the link takes.
    pub bitrate_kbps: u32,
    /// A password viewers may give to be let in, when set.
    pub gate: Option<Arc<dyn crate::gate::Gate>>,
    /// Grants from this agent's server viewers may present instead, when
    /// set. With neither, anyone who reaches the agent is let in.
    pub grants: Option<Arc<Grants>>,
    /// The person at this machine, who allows each session and sees it for
    /// as long as it lasts, when there is one to ask.
    pub host: Option<Arc<Host>>,
}

/// What one video stream sent, for the log.
#[derive(Debug, Default)]
struct VideoStats {
    /// Where the next stream in this session continues numbering.
    next_frame_id: u32,
    /// The rate control's target when it ended, for the next stream to
    /// start from.
    target_kbps: u32,
    frames: u64,
    keyframes: u64,
    datagrams: u64,
    bytes: u64,
}

struct Video {
    pipeline: Pipeline,
    sender: JoinHandle<VideoStats>,
    /// Tells the sender to finish.
    stop: oneshot::Sender<()>,
    /// What it was started with, to start it again the same way.
    settings: Settings,
    started: Instant,
}

impl Video {
    /// Stop, and return the frame id and bitrate the next stream should
    /// start from.
    async fn stop(self) -> Option<(u32, u32)> {
        // The sender first: it lets go of the frame channel, and a pipeline
        // waiting for room in it — the queue full, the viewer gone — gives
        // up and ends. Joining the pipeline first would wait on it for ever.
        let _ = self.stop.send(());
        let stats = self.sender.await.ok();
        self.pipeline.stop().await;
        stats.as_ref().map(ended)
    }
}

/// Log what a stream sent, and return the frame id and bitrate the next
/// one should start from.
fn ended(stats: &VideoStats) -> (u32, u32) {
    tracing::info!(
        frames = stats.frames,
        keyframes = stats.keyframes,
        datagrams = stats.datagrams,
        kib = stats.bytes / 1024,
        kbps = stats.target_kbps,
        "video stream ended"
    );
    (stats.next_frame_id, stats.target_kbps)
}

/// Resolves when the video's sender has finished on its own — the pipeline
/// stopped, or the connection ended — and never while there is no video.
async fn sender_done(video: &mut Option<Video>) -> Option<VideoStats> {
    match video {
        Some(video) => (&mut video.sender).await.ok(),
        None => std::future::pending().await,
    }
}

/// Resolves at `at`, or never if nothing is due.
async fn due(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Read the viewer's control messages into `messages`, the last one being
/// the end of the stream or an error. Reading has a task of its own so the
/// session can wait on its video too: a read cut short would lose the part
/// of a message already taken off the stream.
async fn read_control(
    mut recv: RecvStream,
    messages: mpsc::Sender<nearhand_transport::Result<Option<Control>>>,
) {
    loop {
        let message = recv_message::<Control>(&mut recv).await;
        let last = !matches!(message, Ok(Some(_)));
        if messages.send(message).await.is_err() || last {
            return;
        }
    }
}

/// Serve one viewer, whose control stream is `send` and `recv`.
pub async fn serve(
    conn: Connection,
    (mut send, mut recv): (quinn::SendStream, RecvStream),
    config: &SessionConfig,
) -> Result<()> {
    match recv_message::<Control>(&mut recv).await? {
        Some(Control::Hello { version, .. }) if version == PROTOCOL_VERSION => {}
        Some(Control::Hello { version, .. }) => {
            let reason = format!("agent speaks protocol {PROTOCOL_VERSION}, viewer {version}");
            conn.close(close::VERSION_MISMATCH.into(), reason.as_bytes());
            bail!(reason);
        }
        other => {
            conn.close(close::PROTOCOL.into(), b"expected Hello");
            bail!("expected Hello, got {other:?}");
        }
    }

    let displays = nearhand_capture::displays().context("listing displays")?;
    let codecs = nearhand_codec::supported_encoders();
    let monitors: Vec<Monitor> = displays
        .iter()
        .map(|d| Monitor {
            id: d.id,
            width: d.width,
            height: d.height,
            x: d.x,
            y: d.y,
            primary: d.primary,
        })
        .collect();
    let caps = Caps {
        codecs: codecs.clone(),
        max_width: monitors.iter().map(|m| m.width).max().unwrap_or(0),
        max_height: monitors.iter().map(|m| m.height).max().unwrap_or(0),
        max_fps: MAX_FPS,
    };
    send_message(
        &mut send,
        &Control::Hello {
            version: PROTOCOL_VERSION,
            caps,
        },
    )
    .await?;
    let admitted = if config.gate.is_some() || config.grants.is_some() {
        authenticate(&conn, &mut send, &mut recv, config).await?
    } else {
        Admitted {
            user: None,
            role: Role::Full,
        }
    };
    tracing::info!(user = ?admitted.user, role = %admitted.role, "viewer admitted");
    // Shown to the person at this machine from here until the session ends.
    let _shown = match &config.host {
        Some(host) => Some(approve(&conn, &mut send, host, &admitted).await?),
        None => None,
    };
    send_message(&mut send, &Control::MonitorList(monitors.clone())).await?;

    // Until the viewer picks a monitor, input lands on the primary one.
    let input = match monitors
        .iter()
        .find(|m| m.primary)
        .or(monitors.first())
        .filter(|_| admitted.role.controls())
        .map(|m| Injection::start(target(m)))
    {
        Some(Ok(input)) => Some(input),
        Some(Err(e)) => {
            tracing::warn!(error = %format!("{e:#}"), "input unavailable; the viewer can only watch");
            None
        }
        None => None,
    };
    let (clipboard_tx, clipboard_rx) = mpsc::unbounded_channel();
    let clipboard = if admitted.role.controls() {
        match ClipboardSync::start(move |text| {
            let _ = clipboard_tx.send(Clipboard::Text(text));
        }) {
            Ok(sync) => Some(Arc::new(sync)),
            Err(e) => {
                tracing::warn!(error = %e, "clipboard sync unavailable");
                None
            }
        }
    } else {
        None
    };
    let streams = tokio::spawn(accept_streams(conn.clone(), input.clone(), clipboard));
    let (cursor, cursor_rx) = mpsc::unbounded_channel();
    let cursor_stream = tokio::spawn(send_stream(
        conn.clone(),
        StreamKind::Cursor,
        CURSOR_PRIORITY,
        cursor_rx,
    ));
    let clipboard_stream = tokio::spawn(send_stream(
        conn.clone(),
        StreamKind::Clipboard,
        CLIPBOARD_PRIORITY,
        clipboard_rx,
    ));

    let sent = Arc::new(Mutex::new(Sent::default()));
    // What the viewer allows at most; rate control stays under it.
    let (ceiling, _) = watch::channel(Quality {
        bitrate_kbps: config.bitrate_kbps,
        fps: MAX_FPS,
    });
    let mut start_kbps = config.bitrate_kbps;
    let mut video: Option<Video> = None;
    // Frame ids run on across streams: switching monitors must not reset them,
    // or the viewer would take the new stream for late chunks of the old one.
    let mut next_frame_id: u32 = 0;
    // Video that stopped by itself starts again then, the same way.
    let mut restart: Option<(Instant, Settings)> = None;
    let mut restart_wait = RESTART_FIRST;
    let stream = |first_frame_id| Stream {
        first_frame_id,
        cursor: cursor.clone(),
        sent: sent.clone(),
        ceiling: ceiling.subscribe(),
    };
    let (messages, mut incoming) = mpsc::channel(8);
    let reader = tokio::spawn(read_control(recv, messages));
    let outcome = loop {
        let message = tokio::select! {
            message = incoming.recv() => message,
            stats = sender_done(&mut video) => {
                let Some(stopped) = video.take() else { continue };
                stopped.pipeline.stop().await;
                if let Some(stats) = &stats {
                    (next_frame_id, start_kbps) = ended(stats);
                }
                // A lost connection ends the session through the reader.
                if conn.close_reason().is_some() {
                    continue;
                }
                // Capture or encoding failed, and the pipeline logged why:
                // the viewer keeps control, and the picture comes back.
                if stopped.started.elapsed() >= HEALTHY_RUN {
                    restart_wait = RESTART_FIRST;
                }
                tracing::warn!(retry_in = ?restart_wait, "video stopped by itself; starting it again");
                restart = Some((Instant::now() + restart_wait, stopped.settings));
                restart_wait = (restart_wait * 2).min(RESTART_MAX);
                continue;
            }
            () = due(restart.map(|(at, _)| at)) => {
                let Some((_, settings)) = restart.take() else { continue };
                let settings = Settings {
                    bitrate_kbps: start_kbps,
                    ..settings
                };
                match start_video(&conn, settings, stream(next_frame_id)).await {
                    Ok(started) => video = Some(started),
                    Err(e) => {
                        tracing::warn!(error = %format!("{e:#}"), retry_in = ?restart_wait, "video did not start again");
                        restart = Some((Instant::now() + restart_wait, settings));
                        restart_wait = (restart_wait * 2).min(RESTART_MAX);
                    }
                }
                continue;
            }
        };
        let message = match message {
            Some(Ok(message)) => message,
            Some(Err(_)) if closed_normally(&conn) => break Ok(()),
            Some(Err(e)) => break Err(e.into()),
            // The reader always says how the stream ended before it goes.
            None => break Ok(()),
        };
        match message {
            None | Some(Control::Bye) => break Ok(()),

            Some(Control::StartVideo {
                monitor,
                codec,
                max_fps,
            }) => {
                // The viewer's choice replaces any restart still due.
                restart = None;
                restart_wait = RESTART_FIRST;
                if let Some(running) = video.take()
                    && let Some((next, kbps)) = running.stop().await
                {
                    next_frame_id = next;
                    start_kbps = kbps;
                }
                if !monitors.iter().any(|m| m.id == monitor) {
                    conn.close(close::PROTOCOL.into(), b"no such monitor");
                    break Err(anyhow::anyhow!("viewer asked for monitor {monitor}"));
                }
                if !codecs.contains(&codec) {
                    conn.close(close::PROTOCOL.into(), b"codec not offered");
                    break Err(anyhow::anyhow!("viewer asked for {codec:?}"));
                }
                ceiling.send_modify(|c| c.fps = max_fps.clamp(1, MAX_FPS));
                let settings = Settings {
                    monitor,
                    codec,
                    max_fps: ceiling.borrow().fps,
                    bitrate_kbps: start_kbps,
                };
                match start_video(&conn, settings, stream(next_frame_id)).await {
                    Ok(started) => {
                        video = Some(started);
                        if let (Some(input), Some(m)) =
                            (&input, monitors.iter().find(|m| m.id == monitor))
                        {
                            input.retarget(target(m));
                        }
                    }
                    Err(e) => {
                        let reason = format!("{e:#}");
                        conn.close(close::PIPELINE_FAILED.into(), reason.as_bytes());
                        break Err(e);
                    }
                }
            }

            Some(Control::RequestKeyframe) => {
                if let Some(running) = &video {
                    running.pipeline.request_keyframe();
                }
            }

            // A ceiling for rate control, which picks what the link takes
            // beneath it.
            Some(Control::SetQuality { bitrate_kbps, fps }) => {
                if bitrate_kbps > 0 {
                    ceiling.send_replace(Quality {
                        bitrate_kbps,
                        fps: fps.clamp(1, MAX_FPS),
                    });
                }
            }

            Some(Control::Ping { viewer_us }) => {
                // Answered straight away: any delay here lands in the round
                // trip and widens the viewer's uncertainty.
                let pong = Control::Pong {
                    viewer_us,
                    agent_us: nearhand_capture::clock::now_us(),
                };
                if let Err(e) = send_message(&mut send, &pong).await {
                    break Err(e.into());
                }
            }

            Some(Control::Nack { frame_id, chunks }) => {
                let resend = sent
                    .lock()
                    .map(|sent| sent.chunks(frame_id, &chunks))
                    .unwrap_or_default();
                tracing::trace!(
                    frame_id,
                    requested = chunks.len(),
                    resending = resend.len(),
                    "nack"
                );
                for datagram in resend {
                    if conn.send_datagram(datagram).is_err() {
                        break;
                    }
                }
            }

            // Agent-to-viewer messages, and the handshake's, have no business
            // arriving here.
            Some(
                other @ (Control::Hello { .. }
                | Control::MonitorList(_)
                | Control::Pong { .. }
                | Control::AuthRequired { .. }
                | Control::AwaitingApproval
                | Control::AuthStart { .. }
                | Control::AuthAnswer { .. }
                | Control::AuthProve { .. }
                | Control::AuthProved { .. }
                | Control::Present { .. }),
            ) => {
                conn.close(close::PROTOCOL.into(), b"unexpected message");
                break Err(anyhow::anyhow!("unexpected {other:?}"));
            }
        }
    };

    if let Some(running) = video.take() {
        running.stop().await;
    }
    reader.abort();
    streams.abort();
    cursor_stream.abort();
    clipboard_stream.abort();
    conn.close(close::NORMAL.into(), b"bye");
    outcome
}

/// Who was let in, and what they may do.
struct Admitted {
    /// The server's name for them, when they came with a grant.
    user: Option<String>,
    role: Role,
}

/// Have the viewer prove the password, and prove it back. Neither side ever
/// sends the password: they run the exchange in `nearhand_core::access`,
/// tied to this connection, so a server that stood in the middle of the
/// introduction cannot pass it through. A wrong password ends the
/// connection — each guess costs a whole handshake, and a few wrong ones
/// replace the password.
async fn authenticate(
    conn: &Connection,
    send: &mut quinn::SendStream,
    recv: &mut RecvStream,
    config: &SessionConfig,
) -> Result<Admitted> {
    let refuse = |reason: &str| {
        conn.close(close::AUTH_FAILED.into(), reason.as_bytes());
        anyhow::anyhow!("{reason}")
    };
    send_message(
        send,
        &Control::AuthRequired {
            secret: config.gate.as_ref().map(|gate| gate.secret()),
        },
    )
    .await?;
    let started = match recv_message::<Control>(recv).await? {
        Some(Control::AuthStart { pake }) => pake,
        Some(Control::Present { grant }) => {
            let Some(grants) = &config.grants else {
                return Err(refuse("this device takes a password, not a grant"));
            };
            return match grants.check(&grant) {
                Ok(grant) => Ok(Admitted {
                    user: Some(grant.user),
                    role: grant.role,
                }),
                Err(reason) => Err(refuse(reason)),
            };
        }
        other => {
            conn.close(close::PROTOCOL.into(), b"expected AuthStart");
            bail!("expected AuthStart, got {other:?}");
        }
    };
    let Some(gate) = &config.gate else {
        return Err(refuse(
            "this device has no access password; sign in to its server instead",
        ));
    };
    let material = gate.material().map_err(refuse)?;
    let binding = nearhand_transport::access::binding(conn)
        .map_err(|_| refuse("this connection cannot carry a password exchange"))?;
    let seed = nearhand_transport::access::seed()
        .map_err(|_| refuse("this machine's random number generator failed"))?;
    let (pending, answer) = access::Agent::answer(&material, &binding, seed, &started)
        .map_err(|_| refuse("that is not the start of a password exchange"))?;
    send_message(send, &Control::AuthAnswer { pake: answer }).await?;
    let proof = match recv_message::<Control>(recv).await? {
        Some(Control::AuthProve { proof }) => proof,
        other => {
            conn.close(close::PROTOCOL.into(), b"expected AuthProve");
            bail!("expected AuthProve, got {other:?}");
        }
    };
    match pending.check(&proof) {
        Ok(ours) => {
            gate.accepted();
            // The viewer checks this in turn: without it, it knows the
            // password reached something, not that it reached this agent.
            send_message(
                send,
                &Control::AuthProved {
                    proof: ours.to_vec(),
                },
            )
            .await?;
            // A password is the device's own say-so: everything a session
            // can do.
            Ok(Admitted {
                user: None,
                role: Role::Full,
            })
        }
        Err(_) => match gate.rejected() {
            Verdict::Rejected(reason) => {
                conn.close(close::AUTH_FAILED.into(), reason.as_bytes());
                bail!("{reason}");
            }
            Verdict::Replaced(new) => {
                conn.close(close::AUTH_FAILED.into(), b"wrong password");
                // Printed: the person at this machine has to read out the
                // new one.
                println!("too many wrong passwords; the password is now {new}");
                bail!("wrong password, replaced");
            }
        },
    }
}

/// Ask the person at this machine to allow the session, telling the viewer
/// it is waiting; once allowed, show the session to them.
async fn approve(
    conn: &Connection,
    send: &mut quinn::SendStream,
    host: &Arc<Host>,
    admitted: &Admitted,
) -> Result<InSession> {
    let viewer = match &admitted.user {
        Some(user) => format!(
            "{user} ({}), {}",
            admitted.role,
            describe(conn.remote_address())
        ),
        None => describe(conn.remote_address()),
    };
    if host.asks() {
        send_message(send, &Control::AwaitingApproval).await?;
    }
    let closed = conn.clone();
    if !host
        .ask(&viewer, async move {
            closed.closed().await;
        })
        .await
    {
        conn.close(close::DECLINED.into(), b"the person at the device declined");
        bail!("declined by the person at this machine");
    }
    let ending = conn.clone();
    Ok(host.session_started(&viewer, move || {
        ending.close(
            close::ENDED_BY_HOST.into(),
            b"ended by the person at the device",
        );
    }))
}

/// How the person at this machine is told who is connecting.
fn describe(remote: std::net::SocketAddr) -> String {
    match path_of(remote) {
        Path::Relayed => "a viewer, through the server's relay".to_owned(),
        path => format!("a viewer at {}, {path}", remote.ip().to_canonical()),
    }
}

fn target(monitor: &Monitor) -> nearhand_input::Target {
    nearhand_input::Target {
        width: monitor.width,
        height: monitor.height,
        x: monitor.x,
        y: monitor.y,
    }
}

/// Send one kind of message to the viewer for as long as the session lasts.
async fn send_stream<T: Serialize>(
    conn: Connection,
    kind: StreamKind,
    priority: i32,
    messages: mpsc::UnboundedReceiver<T>,
) {
    if let Err(e) = send_all(&conn, kind, priority, messages).await {
        tracing::debug!(error = %e, ?kind, "stream ended");
    }
}

/// Accept the viewer's unidirectional streams for as long as the connection
/// lasts, each handled by a task of its own.
async fn accept_streams(
    conn: Connection,
    input: Option<Injection>,
    clipboard: Option<Arc<ClipboardSync>>,
) {
    while let Ok(mut recv) = conn.accept_uni().await {
        match recv_message::<StreamKind>(&mut recv).await {
            Ok(Some(StreamKind::Input)) => {
                tracing::debug!("input stream opened");
                tokio::spawn(read_input(conn.clone(), recv, input.clone()));
            }
            Ok(Some(StreamKind::Clipboard)) => {
                tokio::spawn(read_clipboard(conn.clone(), recv, clipboard.clone()));
            }
            // Agent-to-viewer only.
            Ok(Some(StreamKind::Cursor)) => {
                conn.close(close::PROTOCOL.into(), b"unexpected stream");
                return;
            }
            // Opened and finished without a word: nothing to do.
            Ok(None) => {}
            Err(e) => {
                tracing::info!(error = %e, "unreadable stream header");
                conn.close(close::PROTOCOL.into(), b"unknown stream");
                return;
            }
        }
    }
}

/// Apply input events in the order they arrive. Without an injector, as on a
/// platform that has none yet, they are read and dropped.
async fn read_input(conn: Connection, mut recv: RecvStream, input: Option<Injection>) {
    loop {
        match recv_message::<Input>(&mut recv).await {
            Ok(Some(event)) => {
                tracing::trace!(?event, "input");
                if let Some(input) = &input {
                    input.inject(event);
                }
            }
            Ok(None) => return,
            Err(e) => {
                // A lost connection is the session's business; a malformed
                // message is a protocol violation.
                if conn.close_reason().is_none() {
                    tracing::info!(error = %e, "malformed input");
                    conn.close(close::PROTOCOL.into(), b"malformed input");
                }
                return;
            }
        }
    }
}

/// Put the viewer's clipboard text on this machine's clipboard.
async fn read_clipboard(
    conn: Connection,
    mut recv: RecvStream,
    clipboard: Option<Arc<ClipboardSync>>,
) {
    loop {
        match recv_message::<Clipboard>(&mut recv).await {
            Ok(Some(Clipboard::Text(text))) if text.len() > Clipboard::MAX_TEXT => {
                conn.close(close::PROTOCOL.into(), b"clipboard text too large");
                return;
            }
            Ok(Some(Clipboard::Text(text))) => {
                if let Some(clipboard) = &clipboard {
                    clipboard.apply(text);
                }
            }
            Ok(None) => return,
            Err(e) => {
                if conn.close_reason().is_none() {
                    tracing::info!(error = %e, "malformed clipboard message");
                    conn.close(close::PROTOCOL.into(), b"malformed clipboard message");
                }
                return;
            }
        }
    }
}

/// Bytes of video waiting in QUIC's datagram send buffer.
fn backlog(conn: &Connection) -> usize {
    nearhand_transport::DATAGRAM_BUFFER.saturating_sub(conn.datagram_send_buffer_space())
}

/// A stream's rate controller and the pipeline it steers.
struct Rate {
    rate: RateController,
    control: QualityControl,
}

/// Recently sent frames, as the datagrams that carried them.
#[derive(Debug, Default)]
struct Sent {
    frames: VecDeque<(u32, Vec<Bytes>)>,
    bytes: usize,
}

impl Sent {
    fn insert(&mut self, frame_id: u32, datagrams: Vec<Bytes>) {
        self.bytes += datagrams.iter().map(Bytes::len).sum::<usize>();
        self.frames.push_back((frame_id, datagrams));
        while self.frames.len() > SENT_FRAMES || self.bytes > SENT_BYTES {
            let Some((_, old)) = self.frames.pop_front() else {
                break;
            };
            self.bytes -= old.iter().map(Bytes::len).sum::<usize>();
        }
    }

    /// The datagrams for `chunks` of a frame, or all of them if `chunks` is
    /// empty. Nothing for a frame no longer held or indices out of range.
    fn chunks(&self, frame_id: u32, chunks: &[u16]) -> Vec<Bytes> {
        let Some((_, datagrams)) = self.frames.iter().find(|(id, _)| *id == frame_id) else {
            return Vec::new();
        };
        if chunks.is_empty() {
            return datagrams.clone();
        }
        chunks
            .iter()
            .filter_map(|&i| datagrams.get(usize::from(i)).cloned())
            .collect()
    }
}

/// Whether the viewer closed the connection on purpose, rather than it being
/// lost. A viewer that exits without its Bye getting through is still a
/// normal goodbye.
fn closed_normally(conn: &Connection) -> bool {
    matches!(
        conn.close_reason(),
        Some(quinn::ConnectionError::ApplicationClosed(frame))
            if frame.error_code == close::NORMAL.into()
    )
}

/// What a video stream shares with the session around it.
struct Stream {
    first_frame_id: u32,
    cursor: mpsc::UnboundedSender<Cursor>,
    sent: Arc<Mutex<Sent>>,
    ceiling: watch::Receiver<Quality>,
}

async fn start_video(conn: &Connection, settings: Settings, stream: Stream) -> Result<Video> {
    let started = Pipeline::start(settings, stream.cursor.clone()).await?;
    tracing::info!(
        monitor = settings.monitor,
        width = started.width,
        height = started.height,
        fps = settings.max_fps,
        kbps = settings.bitrate_kbps,
        "video started"
    );
    let rate = RateController::new(
        *stream.ceiling.borrow(),
        settings.bitrate_kbps,
        started.width,
        started.height,
    );
    let control = started.pipeline.quality_control();
    let initial = rate.initial();
    if (initial.bitrate_kbps, initial.fps) != (settings.bitrate_kbps, settings.max_fps) {
        control.set(initial.bitrate_kbps, initial.fps);
    }
    let (stop, stopped) = oneshot::channel();
    let sender = tokio::spawn(send_video(
        conn.clone(),
        started.frames,
        stream,
        Rate { rate, control },
        stopped,
    ));
    Ok(Video {
        pipeline: started.pipeline,
        sender,
        stop,
        settings,
        started: Instant::now(),
    })
}

/// Chunk each encoded frame into datagrams and send it.
///
/// `send_datagram` never blocks: under congestion quinn discards the oldest
/// queued datagrams, which is the right policy — the viewer notices the gap and
/// asks for the chunks again, rather than video falling ever further behind.
/// Each frame's datagrams are kept in `sent` for that.
///
/// Every encoded frame consumes a frame id, sent or not. The viewer detects
/// loss by gaps in the ids; a frame skipped here without leaving a gap would
/// have the next P-frame decoded against the wrong reference.
///
/// Ends when told to through `stop`, when the pipeline ends, or when the
/// connection does — whatever QUIC still held for it counts as backlog for
/// ever after, so a lost viewer would otherwise be waited on for good.
async fn send_video(
    conn: Connection,
    mut frames: mpsc::Receiver<nearhand_codec::EncodedFrame>,
    mut stream: Stream,
    rate: Rate,
    mut stop: oneshot::Receiver<()>,
) -> VideoStats {
    let Rate {
        rate: mut controller,
        control,
    } = rate;
    let sent = stream.sent.clone();
    let mut stats = VideoStats {
        next_frame_id: stream.first_frame_id,
        target_kbps: controller.target_kbps(),
        ..VideoStats::default()
    };
    let mut ticker = tokio::time::interval(rate::INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_sample = tokio::time::Instant::now();
    let mut bytes_at_sample = 0;

    loop {
        // While QUIC still holds a lot to send, take no more frames: the
        // frame queue fills, capture pauses, and the frame taken next is
        // fresh. Nothing encoded is dropped, so the reference chain holds.
        let backlogged = backlog(&conn) > rate::backlog_limit(controller.target_kbps());
        let frame = tokio::select! {
            _ = &mut stop => break,
            _ = conn.closed() => break,
            frame = frames.recv(), if !backlogged => match frame {
                Some(frame) => frame,
                None => break,
            },
            _ = tokio::time::sleep(BACKLOG_POLL), if backlogged => continue,
            _ = ticker.tick() => {
                let path = conn.stats().path;
                let sample = rate::Sample {
                    backlog_bytes: backlog(&conn) as u64,
                    rtt: path.rtt,
                    sent_packets: path.sent_packets,
                    lost_packets: path.lost_packets,
                    sent_bytes: stats.bytes,
                };
                let elapsed = last_sample.elapsed();
                last_sample = tokio::time::Instant::now();
                tracing::debug!(
                    target_kbps = controller.target_kbps(),
                    sent_kbps = (stats.bytes - bytes_at_sample) * 8 / 1000 * 1000
                        / (elapsed.as_millis().max(1) as u64),
                    rtt_ms = path.rtt.as_millis() as u64,
                    reading = ?controller.last_reading(),
                    "rate sample"
                );
                bytes_at_sample = stats.bytes;
                if let Some(quality) = controller.update(sample, elapsed) {
                    tracing::info!(
                        kbps = quality.bitrate_kbps,
                        fps = quality.fps,
                        rtt_ms = sample.rtt.as_secs_f64() * 1000.0,
                        baseline_rtt_ms = controller.baseline_rtt().as_secs_f64() * 1000.0,
                        "rate changed"
                    );
                    control.set(quality.bitrate_kbps, quality.fps);
                }
                stats.target_kbps = controller.target_kbps();
                continue;
            }
            Ok(()) = stream.ceiling.changed() => {
                let ceiling = *stream.ceiling.borrow_and_update();
                if let Some(quality) = controller.set_ceiling(ceiling) {
                    control.set(quality.bitrate_kbps, quality.fps);
                }
                stats.target_kbps = controller.target_kbps();
                continue;
            }
        };
        let frame_id = stats.next_frame_id;
        stats.next_frame_id = frame_id.wrapping_add(1);

        let Some(max_datagram) = conn.max_datagram_size() else {
            conn.close(close::PROTOCOL.into(), b"viewer does not accept datagrams");
            break;
        };
        let chunks = match packetize(
            frame_id,
            frame.keyframe,
            frame.capture_ts_us,
            &frame.data,
            max_datagram,
        ) {
            Ok(chunks) => chunks,
            Err(e) => {
                tracing::warn!(error = %e, frame_id, "could not packetize frame; skipping");
                continue;
            }
        };

        let datagrams: Vec<Bytes> = match chunks
            .iter()
            .map(|chunk| encode_chunk(chunk).map(Bytes::from))
            .collect()
        {
            Ok(datagrams) => datagrams,
            Err(e) => {
                tracing::warn!(error = %e, frame_id, "could not encode chunks; skipping");
                continue;
            }
        };
        for datagram in &datagrams {
            stats.bytes += datagram.len() as u64;
            // A clone is a reference count, not a copy.
            if let Err(e) = conn.send_datagram(datagram.clone()) {
                tracing::debug!(error = %e, "datagram send failed; ending video");
                return stats;
            }
            stats.datagrams += 1;
        }
        if let Ok(mut sent) = sent.lock() {
            sent.insert(frame_id, datagrams);
        }

        stats.frames += 1;
        if frame.keyframe {
            stats.keyframes += 1;
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagrams(n: usize, size: usize) -> Vec<Bytes> {
        (0..n).map(|i| Bytes::from(vec![i as u8; size])).collect()
    }

    #[test]
    fn sent_frames_answer_nacks() {
        let mut sent = Sent::default();
        sent.insert(7, datagrams(3, 10));
        assert_eq!(
            sent.chunks(7, &[2, 0]),
            [datagrams(3, 10)[2].clone(), datagrams(3, 10)[0].clone()]
        );
        assert_eq!(sent.chunks(7, &[]).len(), 3, "empty means all");
        assert!(sent.chunks(7, &[3]).is_empty(), "out of range");
        assert!(sent.chunks(8, &[0]).is_empty(), "never sent");
    }

    #[test]
    fn sent_frames_are_bounded() {
        let mut sent = Sent::default();
        for id in 0..(SENT_FRAMES as u32 + 5) {
            sent.insert(id, datagrams(1, 10));
        }
        assert_eq!(sent.frames.len(), SENT_FRAMES);
        assert!(sent.chunks(0, &[]).is_empty(), "oldest dropped");

        sent.insert(1000, datagrams(1, SENT_BYTES));
        assert!(sent.bytes <= SENT_BYTES);
        assert_eq!(sent.chunks(1000, &[]).len(), 1);
    }

    /// Both ends of a QUIC connection over loopback: the agent's, the
    /// viewer's, and the endpoints that keep them up.
    async fn connected() -> (Connection, Connection, [quinn::Endpoint; 2]) {
        use nearhand_transport::{Identity, client_endpoint, connect, server_endpoint};
        let identity = Identity::generate().expect("identity");
        let loopback = "127.0.0.1:0".parse().expect("address");
        let agent = server_endpoint(loopback, &identity).expect("agent endpoint");
        let address = agent.local_addr().expect("agent address");
        let viewer = client_endpoint(address).expect("viewer endpoint");
        let (agent_side, viewer_side) = tokio::join!(
            async {
                agent
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("handshake")
            },
            async {
                connect(&viewer, address, identity.fingerprint())
                    .await
                    .expect("connect")
            },
        );
        (agent_side, viewer_side, [agent, viewer])
    }

    /// What a video sender needs besides its connection and frames.
    fn video_stream() -> (Stream, Rate) {
        let quality = Quality {
            bitrate_kbps: 8000,
            fps: 60,
        };
        let (cursor, _) = mpsc::unbounded_channel();
        let stream = Stream {
            first_frame_id: 0,
            cursor,
            sent: Arc::default(),
            ceiling: watch::channel(quality).1,
        };
        let rate = Rate {
            rate: RateController::new(quality, quality.bitrate_kbps, 1920, 1080),
            control: QualityControl::detached(),
        };
        (stream, rate)
    }

    /// The agent's side of letting a viewer in, against a viewer that
    /// types `typed`: what the agent made of it, and whether the viewer
    /// could prove the agent knows the password too.
    async fn password_exchange(typed: &str) -> (Result<Admitted>, bool) {
        use nearhand_core::access;

        let (agent_conn, viewer_conn, _endpoints) = connected().await;
        let config = Arc::new(SessionConfig {
            bitrate_kbps: 4000,
            gate: Some(Arc::new(crate::password::Password::new())),
            grants: None,
            host: None,
        });
        let shown = config
            .gate
            .as_ref()
            .expect("a gate")
            .material()
            .expect("the password it shows");
        let typed = typed.replace("{shown}", &String::from_utf8_lossy(&shown));

        let agent_side = tokio::spawn(async move {
            let (mut send, mut recv) = agent_conn.accept_bi().await.expect("stream");
            // `serve` has read the viewer's Hello by this point.
            let _: Option<Control> = recv_message(&mut recv).await.expect("hello");
            let outcome = authenticate(&agent_conn, &mut send, &mut recv, &config).await;
            // Held as `serve` holds them: a stream dropped unfinished is
            // reset, and the last message with it.
            (outcome, agent_conn, send, recv)
        });

        let viewer_side = tokio::spawn(async move {
            let (mut send, mut recv) = viewer_conn.open_bi().await.expect("stream");
            send_message(
                &mut send,
                &Control::Hello {
                    version: PROTOCOL_VERSION,
                    caps: Caps {
                        codecs: Vec::new(),
                        max_width: 0,
                        max_height: 0,
                        max_fps: 0,
                    },
                },
            )
            .await
            .expect("hello");
            let Some(Control::AuthRequired {
                secret: Some(secret),
            }) = recv_message(&mut recv).await.expect("what to prove")
            else {
                panic!("expected AuthRequired with a password");
            };
            let material = secret.material(&typed).expect("material");
            let binding = nearhand_transport::access::binding(&viewer_conn).expect("binding");
            let seed = nearhand_transport::access::seed().expect("seed");
            let (viewer, start) = access::Viewer::start(&material, &binding, seed);
            send_message(&mut send, &Control::AuthStart { pake: start })
                .await
                .expect("start");
            let Ok(Some(Control::AuthAnswer { pake })) = recv_message(&mut recv).await else {
                return false;
            };
            let (viewer, proof) = viewer.prove(&pake).expect("prove");
            send_message(
                &mut send,
                &Control::AuthProve {
                    proof: proof.to_vec(),
                },
            )
            .await
            .expect("proof");
            match recv_message(&mut recv).await {
                Ok(Some(Control::AuthProved { proof })) => viewer.check(&proof).is_ok(),
                // A wrong password: the agent has closed by now.
                _ => false,
            }
        });
        let (agent_side, proved) = tokio::join!(agent_side, viewer_side);
        let (admitted, ..) = agent_side.expect("the agent's side");
        (admitted, proved.expect("the viewer's side"))
    }

    /// The password is proved, never sent, and both sides end up sure of
    /// each other.
    #[tokio::test]
    async fn a_viewer_with_the_password_is_let_in() {
        let (admitted, proved) = password_exchange("{shown}").await;
        let admitted = admitted.expect("let in");
        assert!(
            admitted.user.is_none(),
            "a password is nobody in particular"
        );
        assert!(matches!(admitted.role, Role::Full));
        assert!(proved, "the agent did not prove itself back");
    }

    #[tokio::test]
    async fn a_viewer_with_another_password_is_not() {
        let (admitted, proved) = password_exchange("000000 is not it").await;
        assert!(admitted.is_err(), "let in with the wrong password");
        assert!(!proved);
    }

    /// A lost viewer ends the video, though the pipeline is still there
    /// and QUIC may still count unsent datagrams against the connection.
    #[tokio::test]
    async fn video_ends_with_the_connection() {
        let (agent, viewer, _endpoints) = connected().await;
        let (_pipeline, frames) = mpsc::channel(4);
        let (_stop, stop) = oneshot::channel();
        let (stream, rate) = video_stream();
        let sender = tokio::spawn(send_video(agent, frames, stream, rate, stop));
        viewer.close(close::NORMAL.into(), b"bye");
        tokio::time::timeout(Duration::from_secs(5), sender)
            .await
            .expect("the sender ends")
            .expect("the sender task");
    }

    /// Told to stop, the sender lets go of the frame channel: a pipeline
    /// waiting for room in it hears so, and can be joined.
    #[tokio::test]
    async fn stopped_video_frees_the_pipeline() {
        let (agent, _viewer, _endpoints) = connected().await;
        let (pipeline, frames) = mpsc::channel(4);
        let (stop, stopped) = oneshot::channel();
        let (stream, rate) = video_stream();
        let sender = tokio::spawn(send_video(agent, frames, stream, rate, stopped));
        stop.send(()).expect("the sender listens");
        tokio::time::timeout(Duration::from_secs(5), sender)
            .await
            .expect("the sender ends")
            .expect("the sender task");
        assert!(pipeline.is_closed());
    }

    /// The viewer's control messages come through in order, and then how
    /// the stream ended.
    #[tokio::test]
    async fn control_messages_are_read_through_to_the_end() {
        let (agent, viewer, _endpoints) = connected().await;
        let (mut send, _) = viewer.open_bi().await.expect("stream");
        send_message(&mut send, &Control::RequestKeyframe)
            .await
            .expect("send");
        send_message(&mut send, &Control::Bye).await.expect("send");
        send.finish().expect("finish");
        let (_, recv) = agent.accept_bi().await.expect("accept");
        let (messages, mut incoming) = mpsc::channel(1);
        let reader = tokio::spawn(read_control(recv, messages));
        let mut read = Vec::new();
        while let Some(message) = incoming.recv().await {
            read.push(message.expect("read"));
        }
        assert_eq!(
            read,
            [Some(Control::RequestKeyframe), Some(Control::Bye), None]
        );
        reader.await.expect("the reader ends");
    }
}
