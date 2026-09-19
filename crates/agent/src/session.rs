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

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use nearhand_clipboard::ClipboardSync;
use nearhand_core::proto::close;
use nearhand_core::video::{encode_chunk, packetize};
use nearhand_core::{
    Caps, Clipboard, Control, Cursor, Input, Monitor, PROTOCOL_VERSION, StreamKind,
};
use nearhand_transport::rendezvous::{Path, path_of};
use nearhand_transport::{recv_message, send_all, send_message};
use quinn::{Connection, RecvStream};
use serde::Serialize;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::gate::{Gate, Verdict};
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

/// Stream priorities, highest first. Clipboard text can be large and must
/// never hold up the pointer.
const CURSOR_PRIORITY: i32 = 0;
const CLIPBOARD_PRIORITY: i32 = -1;

pub struct SessionConfig {
    /// The most video bitrate to use; rate control picks what the link takes.
    pub bitrate_kbps: u32,
    /// What viewers must give before anything else, when set.
    pub gate: Option<Arc<dyn Gate>>,
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
}

impl Video {
    /// Stop, and return the frame id and bitrate the next stream should
    /// start from.
    async fn stop(self) -> Option<(u32, u32)> {
        self.pipeline.stop().await;
        // The pipeline dropped its end of the frame channel, so the sender
        // drains and finishes on its own.
        let stats = self.sender.await.ok()?;
        tracing::info!(
            frames = stats.frames,
            keyframes = stats.keyframes,
            datagrams = stats.datagrams,
            kib = stats.bytes / 1024,
            kbps = stats.target_kbps,
            "video stream ended"
        );
        Some((stats.next_frame_id, stats.target_kbps))
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
    if let Some(gate) = &config.gate {
        authenticate(&conn, &mut send, &mut recv, gate).await?;
    }
    // Shown to the person at this machine from here until the session ends.
    let _shown = match &config.host {
        Some(host) => Some(approve(&conn, &mut send, host).await?),
        None => None,
    };
    send_message(&mut send, &Control::MonitorList(monitors.clone())).await?;

    // Until the viewer picks a monitor, input lands on the primary one.
    let input = match monitors
        .iter()
        .find(|m| m.primary)
        .or(monitors.first())
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
    let clipboard = match ClipboardSync::start(move |text| {
        let _ = clipboard_tx.send(Clipboard::Text(text));
    }) {
        Ok(sync) => Some(Arc::new(sync)),
        Err(e) => {
            tracing::warn!(error = %e, "clipboard sync unavailable");
            None
        }
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
    let outcome = loop {
        let message = match recv_message::<Control>(&mut recv).await {
            Ok(message) => message,
            Err(_) if closed_normally(&conn) => break Ok(()),
            Err(e) => break Err(e.into()),
        };
        match message {
            None | Some(Control::Bye) => break Ok(()),

            Some(Control::StartVideo {
                monitor,
                codec,
                max_fps,
            }) => {
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
                let stream = Stream {
                    first_frame_id: next_frame_id,
                    cursor: cursor.clone(),
                    sent: sent.clone(),
                    ceiling: ceiling.subscribe(),
                };
                match start_video(&conn, settings, stream).await {
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
                | Control::AuthRequired
                | Control::AwaitingApproval
                | Control::Authenticate { .. }),
            ) => {
                conn.close(close::PROTOCOL.into(), b"unexpected message");
                break Err(anyhow::anyhow!("unexpected {other:?}"));
            }
        }
    };

    if let Some(running) = video.take() {
        running.stop().await;
    }
    streams.abort();
    cursor_stream.abort();
    clipboard_stream.abort();
    conn.close(close::NORMAL.into(), b"bye");
    outcome
}

/// Ask for the password and check it. A wrong one ends the connection: each
/// guess costs a whole handshake, and a few wrong ones replace the password.
async fn authenticate(
    conn: &Connection,
    send: &mut quinn::SendStream,
    recv: &mut RecvStream,
    gate: &Arc<dyn Gate>,
) -> Result<()> {
    send_message(send, &Control::AuthRequired).await?;
    let attempt = match recv_message::<Control>(recv).await? {
        Some(Control::Authenticate { password }) => password,
        other => {
            conn.close(close::PROTOCOL.into(), b"expected Authenticate");
            bail!("expected Authenticate, got {other:?}");
        }
    };
    let verdict = if gate.is_slow() {
        let gate = gate.clone();
        tokio::task::spawn_blocking(move || gate.check(&attempt)).await?
    } else {
        gate.check(&attempt)
    };
    match verdict {
        Verdict::Accepted => Ok(()),
        Verdict::Rejected(reason) => {
            conn.close(close::AUTH_FAILED.into(), reason.as_bytes());
            bail!("{reason}");
        }
        Verdict::Replaced(new) => {
            conn.close(close::AUTH_FAILED.into(), b"wrong password");
            // Printed: the person at this machine has to read out the new one.
            println!("too many wrong passwords; the password is now {new}");
            bail!("wrong password, replaced");
        }
    }
}

/// Ask the person at this machine to allow the session, telling the viewer
/// it is waiting; once allowed, show the session to them.
async fn approve(
    conn: &Connection,
    send: &mut quinn::SendStream,
    host: &Arc<Host>,
) -> Result<InSession> {
    let viewer = describe(conn.remote_address());
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
    let sender = tokio::spawn(send_video(
        conn.clone(),
        started.frames,
        stream,
        Rate { rate, control },
    ));
    Ok(Video {
        pipeline: started.pipeline,
        sender,
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
async fn send_video(
    conn: Connection,
    mut frames: mpsc::Receiver<nearhand_codec::EncodedFrame>,
    mut stream: Stream,
    rate: Rate,
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
}
