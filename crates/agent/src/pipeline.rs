//! Capture and encode on a dedicated thread.
//!
//! The capturer and encoder are COM objects bound to the thread that made them,
//! and every call on them blocks, so they get an OS thread of their own rather
//! than a place on the async runtime. The thread talks to the session through
//! channels: commands in, encoded frames and pointer changes out.

use std::sync::mpsc::{self, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use nearhand_capture::{Capturer, Frame};
use nearhand_codec::{EncodedFrame, Encoder, EncoderConfig};
use nearhand_core::{Codec, Cursor};
use tokio::sync::{mpsc as async_mpsc, oneshot};

/// How long one capture wait lasts. Bounds how late a command is noticed while
/// the desktop is idle — a keyframe request included — without the thread
/// spinning: an idle wait costs one kernel wakeup, not CPU.
const CAPTURE_WAIT: Duration = Duration::from_millis(50);

/// Encoded frames in flight between this thread and the network task. Small
/// on purpose: if the network cannot keep up, capture should slow down rather
/// than frames queueing up and arriving late.
const FRAME_QUEUE: usize = 4;

#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub monitor: u8,
    pub codec: Codec,
    pub max_fps: u8,
    pub bitrate_kbps: u32,
}

enum Command {
    Keyframe,
    Quality { bitrate_kbps: u32, fps: u8 },
}

/// Changes a running pipeline's bitrate and frame rate.
#[derive(Clone)]
pub struct QualityControl(mpsc::Sender<Command>);

impl QualityControl {
    pub fn set(&self, bitrate_kbps: u32, fps: u8) {
        // Fails only once the pipeline has stopped.
        let _ = self.0.send(Command::Quality { bitrate_kbps, fps });
    }
}

/// A running pipeline. Stop it with [`Pipeline::stop`]; dropping it also
/// stops the thread, just without waiting for it.
pub struct Pipeline {
    commands: mpsc::Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

pub struct Started {
    pub pipeline: Pipeline,
    pub frames: async_mpsc::Receiver<EncodedFrame>,
    pub width: u16,
    pub height: u16,
}

impl Pipeline {
    /// Start capturing and encoding. Resolves once the first frame has been
    /// captured and the encoder is up, so setup failures surface here.
    ///
    /// Pointer changes go to `cursor`, which outlives the pipeline: the
    /// session keeps one cursor stream across monitor switches.
    pub async fn start(
        settings: Settings,
        cursor: async_mpsc::UnboundedSender<Cursor>,
    ) -> Result<Started> {
        let (commands, command_rx) = mpsc::channel();
        let (frame_tx, frames) = async_mpsc::channel(FRAME_QUEUE);
        let (ready_tx, ready_rx) = oneshot::channel();

        let thread = std::thread::Builder::new()
            .name("nearhand-pipeline".to_owned())
            .spawn(move || run(settings, command_rx, frame_tx, cursor, ready_tx))
            .context("spawning the pipeline thread")?;

        let (width, height) = match ready_rx.await {
            Ok(Ok(size)) => size,
            Ok(Err(reason)) => return Err(anyhow!(reason)),
            Err(_) => return Err(anyhow!("pipeline thread exited during startup")),
        };

        Ok(Started {
            pipeline: Pipeline {
                commands,
                thread: Some(thread),
            },
            frames,
            width,
            height,
        })
    }

    pub fn request_keyframe(&self) {
        let _ = self.commands.send(Command::Keyframe);
    }

    /// A handle that can change the quality from another task — the rate
    /// controller's — for as long as the pipeline runs.
    pub fn quality_control(&self) -> QualityControl {
        QualityControl(self.commands.clone())
    }

    /// Stop the thread and wait for it, so its capture duplication and
    /// hardware encoder session are released before a new pipeline starts.
    pub async fn stop(mut self) {
        let thread = self.thread.take();
        // Dropping self drops the command sender, which is the stop signal.
        drop(self);
        if let Some(thread) = thread {
            let _ = tokio::task::spawn_blocking(move || thread.join()).await;
        }
    }
}

fn run(
    settings: Settings,
    commands: mpsc::Receiver<Command>,
    frames: async_mpsc::Sender<EncodedFrame>,
    cursor: async_mpsc::UnboundedSender<Cursor>,
    ready: oneshot::Sender<std::result::Result<(u16, u16), String>>,
) {
    let Parts {
        mut capturer,
        mut encoder,
        first,
    } = match setup(&settings) {
        Ok(parts) => parts,
        Err(e) => {
            let _ = ready.send(Err(format!("{e:#}")));
            return;
        }
    };
    let _ = ready.send(Ok((first.width, first.height)));
    // Pointer changes are rare and small, so they go out unthrottled; a
    // closed channel just means the session is winding down.
    let forward_pointer = |capturer: &mut Box<dyn Capturer>| {
        for change in capturer.take_pointer() {
            let _ = cursor.send(change);
        }
    };
    forward_pointer(&mut capturer);
    tracing::info!(
        monitor = settings.monitor,
        width = first.width,
        height = first.height,
        "pipeline running"
    );

    let mut interval = frame_interval(settings.max_fps);
    let mut next_slot = Instant::now();
    // When the pending frame was acquired: the frame-rate cap counts from
    // here, not from when encoding finished. Counting from the end of encoding
    // made each cycle interval + encode time — at a 60 fps cap with a 7.7 ms
    // encode that missed every third vsync (40 fps) and held each change up
    // to 7 ms longer (p50 18.5 ms against 12.8 ms, measured).
    let mut acquired_at = Instant::now();
    let mut pending = Some(first);
    // The last frame encoded. Its texture still holds the current desktop, so
    // a keyframe can be produced on demand even when nothing is changing.
    let mut last: Option<Frame> = None;
    // Whether capture is waiting for a desktop it may not see to go away.
    let mut blocked = false;

    loop {
        loop {
            match commands.try_recv() {
                Ok(Command::Keyframe) => {
                    encoder.request_keyframe();
                    // On an idle desktop no new frame would come to carry the
                    // keyframe, and the viewer would stay stuck. Re-encode the
                    // last one instead.
                    if pending.is_none() {
                        pending = last.take();
                    }
                }
                Ok(Command::Quality { bitrate_kbps, fps }) => {
                    if let Err(e) = encoder.set_quality(bitrate_kbps, fps) {
                        tracing::warn!(error = %e, "encoder rejected quality change");
                    }
                    interval = frame_interval(fps);
                }
                Err(TryRecvError::Empty) => break,
                // The session is gone.
                Err(TryRecvError::Disconnected) => return,
            }
        }

        if let Some(frame) = pending.take() {
            match encoder.encode(&frame) {
                Ok(Some(encoded)) => {
                    if frames.blocking_send(encoded).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(error = %e, "encoding failed; stopping the pipeline");
                    return;
                }
            }
            last = Some(frame);
            next_slot = acquired_at + interval;
        }

        // Frame-rate cap. Nothing is lost by waiting: duplication accumulates
        // changes, so the next acquire returns the newest desktop image. With
        // the cap at the display's refresh rate the wait ends about when the
        // next composition arrives anyway, so it costs next to no latency.
        let now = Instant::now();
        if now < next_slot {
            std::thread::sleep(next_slot - now);
        }

        let captured = capturer.next_frame(CAPTURE_WAIT);
        forward_pointer(&mut capturer);
        match captured {
            Ok(Some(frame)) => {
                acquired_at = Instant::now();
                pending = Some(frame);
            }
            Ok(None) => {}
            Err(nearhand_capture::Error::SourceLost) => {
                // The capturer has already rebuilt its duplication. The new
                // one starts with a full frame, so nothing needs forcing.
                tracing::info!("capture source changed; continuing");
                blocked = false;
            }
            Err(nearhand_capture::Error::Blocked(which)) => {
                // The viewer keeps the last picture until the desktop comes
                // back; worth one line in the log, not one per retry.
                if !blocked {
                    tracing::info!(desktop = %which, "cannot capture this desktop; waiting");
                    blocked = true;
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "capture failed; stopping the pipeline");
                return;
            }
        }
    }
}

/// Everything the pipeline thread owns, built on that thread.
struct Parts {
    capturer: Box<dyn Capturer>,
    encoder: Box<dyn Encoder>,
    first: Frame,
}

fn setup(settings: &Settings) -> Result<Parts> {
    let mut capturer = nearhand_capture::open(settings.monitor)
        .with_context(|| format!("opening display {}", settings.monitor))?;

    // The first acquire after duplication starts returns the full desktop
    // straight away; it also tells us the size to encode at.
    let deadline = Instant::now() + Duration::from_secs(2);
    let first = loop {
        if let Some(frame) = capturer.next_frame(Duration::from_millis(250))? {
            break frame;
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "display {} produced no first frame",
                settings.monitor
            ));
        }
    };

    let encoder = nearhand_codec::encoder(EncoderConfig {
        codec: settings.codec,
        width: first.width,
        height: first.height,
        bitrate_kbps: settings.bitrate_kbps,
        max_fps: settings.max_fps,
    })
    .context("opening the encoder")?;

    Ok(Parts {
        capturer,
        encoder,
        first,
    })
}

fn frame_interval(fps: u8) -> Duration {
    Duration::from_secs(1) / u32::from(fps.max(1))
}
