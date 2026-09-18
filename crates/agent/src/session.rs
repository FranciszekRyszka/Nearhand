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
//! A protocol violation closes the connection with a code from
//! [`nearhand_core::proto::close`] and a reason the viewer can show.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use nearhand_core::proto::close;
use nearhand_core::video::{encode_chunk, packetize};
use nearhand_core::{Caps, Control, Monitor, PROTOCOL_VERSION};
use nearhand_transport::{recv_message, send_message};
use quinn::Connection;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::pipeline::{Pipeline, Settings};

/// Highest frame rate a viewer may ask for.
const MAX_FPS: u8 = 120;

pub struct SessionConfig {
    pub bitrate_kbps: u32,
}

/// What one video stream sent, for the log.
#[derive(Debug, Default)]
struct VideoStats {
    /// Where the next stream in this session continues numbering.
    next_frame_id: u32,
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
    /// Stop, and return the frame id the next stream should start from.
    async fn stop(self) -> Option<u32> {
        self.pipeline.stop().await;
        // The pipeline dropped its end of the frame channel, so the sender
        // drains and finishes on its own.
        let stats = self.sender.await.ok()?;
        tracing::info!(
            frames = stats.frames,
            keyframes = stats.keyframes,
            datagrams = stats.datagrams,
            kib = stats.bytes / 1024,
            "video stream ended"
        );
        Some(stats.next_frame_id)
    }
}

pub async fn serve(conn: Connection, config: &SessionConfig) -> Result<()> {
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .context("waiting for the control stream")?;

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
    send_message(&mut send, &Control::MonitorList(monitors.clone())).await?;

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
                    && let Some(next) = running.stop().await
                {
                    next_frame_id = next;
                }
                if !monitors.iter().any(|m| m.id == monitor) {
                    conn.close(close::PROTOCOL.into(), b"no such monitor");
                    break Err(anyhow::anyhow!("viewer asked for monitor {monitor}"));
                }
                if !codecs.contains(&codec) {
                    conn.close(close::PROTOCOL.into(), b"codec not offered");
                    break Err(anyhow::anyhow!("viewer asked for {codec:?}"));
                }
                let settings = Settings {
                    monitor,
                    codec,
                    max_fps: max_fps.clamp(1, MAX_FPS),
                    bitrate_kbps: config.bitrate_kbps,
                };
                match start_video(&conn, settings, next_frame_id).await {
                    Ok(started) => video = Some(started),
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

            Some(Control::SetQuality { bitrate_kbps, fps }) => {
                if let Some(running) = &video
                    && bitrate_kbps > 0
                {
                    running
                        .pipeline
                        .set_quality(bitrate_kbps, fps.clamp(1, MAX_FPS));
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

            // Agent-to-viewer messages have no business arriving here.
            Some(
                other @ (Control::Hello { .. } | Control::MonitorList(_) | Control::Pong { .. }),
            ) => {
                conn.close(close::PROTOCOL.into(), b"unexpected message");
                break Err(anyhow::anyhow!("unexpected {other:?}"));
            }
        }
    };

    if let Some(running) = video.take() {
        running.stop().await;
    }
    conn.close(close::NORMAL.into(), b"bye");
    outcome
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

async fn start_video(conn: &Connection, settings: Settings, first_frame_id: u32) -> Result<Video> {
    let started = Pipeline::start(settings).await?;
    tracing::info!(
        monitor = settings.monitor,
        width = started.width,
        height = started.height,
        fps = settings.max_fps,
        kbps = settings.bitrate_kbps,
        "video started"
    );
    let sender = tokio::spawn(send_video(conn.clone(), started.frames, first_frame_id));
    Ok(Video {
        pipeline: started.pipeline,
        sender,
    })
}

/// Chunk each encoded frame into datagrams and send it.
///
/// `send_datagram` never blocks: under congestion quinn discards the oldest
/// queued datagrams, which is the right policy — the viewer notices the gap and
/// asks for a keyframe, rather than video falling ever further behind.
///
/// Every encoded frame consumes a frame id, sent or not. The viewer detects
/// loss by gaps in the ids; a frame skipped here without leaving a gap would
/// have the next P-frame decoded against the wrong reference.
async fn send_video(
    conn: Connection,
    mut frames: mpsc::Receiver<nearhand_codec::EncodedFrame>,
    first_frame_id: u32,
) -> VideoStats {
    let mut stats = VideoStats {
        next_frame_id: first_frame_id,
        ..VideoStats::default()
    };

    while let Some(frame) = frames.recv().await {
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

        for chunk in &chunks {
            let datagram = match encode_chunk(chunk) {
                Ok(datagram) => datagram,
                Err(e) => {
                    tracing::warn!(error = %e, "could not encode chunk");
                    // The rest of the frame is useless without this chunk.
                    break;
                }
            };
            stats.bytes += datagram.len() as u64;
            if let Err(e) = conn.send_datagram(Bytes::from(datagram)) {
                tracing::debug!(error = %e, "datagram send failed; ending video");
                return stats;
            }
            stats.datagrams += 1;
        }

        stats.frames += 1;
        if frame.keyframe {
            stats.keyframes += 1;
        }
    }
    stats
}
