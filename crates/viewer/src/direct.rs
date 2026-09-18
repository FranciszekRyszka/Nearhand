//! `nearhand-viewer direct`: connect straight to an agent on the LAN (M0).
//!
//! This is the network half of the viewer: handshake, video datagrams in,
//! reassembly, keyframe recovery. Decoding and presenting frames on screen is
//! the next M0 step; until then frames can be written to an Annex B file with
//! `--record`, which any H.264 decoder will play.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nearhand_core::proto::close;
use nearhand_core::video::{Reassembler, decode_chunk};
use nearhand_core::{Caps, Codec, Control, PROTOCOL_VERSION};
use nearhand_transport::{Fingerprint, client_endpoint, connect, recv_message, send_message};
use quinn::{Connection, ConnectionError, RecvStream};
use tokio::sync::mpsc;

/// A frame still missing chunks after this long with no datagrams at all is
/// abandoned. Without it, loss at the end of a burst would go unnoticed until
/// the screen next changes, possibly seconds later.
const PARTIAL_TIMEOUT: Duration = Duration::from_millis(100);

/// Keyframes are expensive; ask at most this often. A keyframe takes an RTT
/// plus an encode to arrive, and asking again sooner only produces two.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(250);

const TICK: Duration = Duration::from_millis(50);

pub struct Options {
    pub address: SocketAddr,
    pub fingerprint: Fingerprint,
    pub monitor: u8,
    pub fps: u8,
    pub seconds: Option<u64>,
    pub record: Option<PathBuf>,
    /// Diagnostic: discard this percentage of incoming datagrams, to exercise
    /// loss recovery on a network that does not lose any.
    pub simulate_loss: u8,
}

pub async fn run(options: Options) -> Result<()> {
    let endpoint = client_endpoint(options.address)?;
    let conn = connect(&endpoint, options.address, options.fingerprint)
        .await
        .with_context(|| format!("connecting to {}", options.address))?;
    println!("connected to {} (rtt {:?})", options.address, conn.rtt());

    let (mut send, mut recv) = conn.open_bi().await?;
    send_message(
        &mut send,
        &Control::Hello {
            version: PROTOCOL_VERSION,
            caps: Caps {
                codecs: nearhand_codec::supported_decoders(),
                max_width: u16::MAX,
                max_height: u16::MAX,
                max_fps: options.fps,
            },
        },
    )
    .await?;

    let agent_caps = match recv_message::<Control>(&mut recv).await {
        Ok(Some(Control::Hello { version, caps })) if version == PROTOCOL_VERSION => caps,
        Ok(Some(Control::Hello { version, .. })) => {
            bail!("agent speaks protocol {version}, this viewer {PROTOCOL_VERSION}")
        }
        Ok(other) => bail!("expected Hello, got {other:?}"),
        Err(e) => return Err(explain(&conn, e.into())),
    };
    match recv_message::<Control>(&mut recv).await? {
        Some(Control::MonitorList(monitors)) => {
            for m in &monitors {
                let marker = if m.id == options.monitor { "▶" } else { " " };
                let primary = if m.primary { " (primary)" } else { "" };
                println!(
                    " {marker} [{}] {}x{} at {},{}{primary}",
                    m.id, m.width, m.height, m.x, m.y
                );
            }
        }
        other => bail!("expected MonitorList, got {other:?}"),
    }
    if !agent_caps.codecs.contains(&Codec::H264) {
        bail!("agent offers no H.264 encoder ({:?})", agent_caps.codecs);
    }

    send_message(
        &mut send,
        &Control::StartVideo {
            monitor: options.monitor,
            codec: Codec::H264,
            max_fps: options.fps,
        },
    )
    .await?;

    // Read control messages on their own task: a stream read is not
    // cancel-safe, and inside `select!` a half-read length prefix would be
    // dropped and corrupt the framing.
    let (control_tx, mut control_rx) = mpsc::channel(16);
    tokio::spawn(read_control(recv, control_tx));

    let mut recording = match &options.record {
        Some(path) => Some(BufWriter::new(
            File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => None,
    };

    let mut reassembler = Reassembler::new();
    let mut loss = LossSimulator::new(options.simulate_loss);
    let mut stats = Stats::new();
    let started = Instant::now();
    let deadline = options.seconds.map(|s| started + Duration::from_secs(s));
    let mut last_datagram = Instant::now();
    let mut keyframe_needed = false;
    let mut last_keyframe_request: Option<Instant> = None;
    let mut ticker = tokio::time::interval(TICK);
    // One listener for the whole session: a fresh one per iteration could miss
    // a Ctrl+C that lands between iterations.
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let outcome: Result<()> = loop {
        tokio::select! {
            datagram = conn.read_datagram() => {
                let datagram = match datagram {
                    Ok(datagram) => datagram,
                    Err(e) => break Err(explain(&conn, e.into())),
                };
                last_datagram = Instant::now();
                stats.datagrams += 1;
                stats.bytes += datagram.len() as u64;
                if loss.drop_this() {
                    stats.simulated_drops += 1;
                    continue;
                }
                let chunk = match decode_chunk(&datagram) {
                    Ok(chunk) => chunk,
                    Err(_) => {
                        stats.undecodable += 1;
                        continue;
                    }
                };
                if let Some(frame) = reassembler.push(chunk) {
                    stats.frames += 1;
                    stats.window_frames += 1;
                    if frame.keyframe {
                        stats.keyframes += 1;
                    }
                    if let Some(out) = recording.as_mut() {
                        out.write_all(&frame.data).context("writing the recording")?;
                    }
                }
            }

            message = control_rx.recv() => match message {
                Some(Ok(Control::MonitorList(monitors))) => {
                    tracing::info!(count = monitors.len(), "monitor list updated");
                }
                Some(Ok(other)) => tracing::debug!(?other, "control message"),
                Some(Err(e)) => break Err(explain(&conn, e.into())),
                // The agent closed its side of the control stream.
                None => break Ok(()),
            },

            _ = ticker.tick() => {
                if reassembler.has_partial() && last_datagram.elapsed() > PARTIAL_TIMEOUT {
                    reassembler.abandon_partials();
                }
                if stats.window_started.elapsed() >= Duration::from_secs(1) {
                    stats.print_window(started.elapsed(), &reassembler, &conn);
                }
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    break Ok(());
                }
            }

            _ = &mut ctrl_c => break Ok(()),
        }

        keyframe_needed |= reassembler.take_keyframe_request();
        let may_ask =
            last_keyframe_request.is_none_or(|t| t.elapsed() >= KEYFRAME_REQUEST_INTERVAL);
        if keyframe_needed && may_ask {
            send_message(&mut send, &Control::RequestKeyframe).await?;
            stats.keyframe_requests += 1;
            last_keyframe_request = Some(Instant::now());
            keyframe_needed = false;
        }
    };

    // Say goodbye and let the agent close first. Closing straight away would
    // discard the Bye before it left, since a QUIC close drops unsent stream
    // data, and the agent would log a lost connection instead of a clean exit.
    let _ = send_message(&mut send, &Control::Bye).await;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_secs(1), conn.closed()).await;
    conn.close(close::NORMAL.into(), b"viewer leaving");
    if let Some(mut out) = recording {
        out.flush().context("flushing the recording")?;
    }
    endpoint.wait_idle().await;

    stats.print_summary(started.elapsed(), &reassembler, options.record.as_deref());
    outcome
}

async fn read_control(mut recv: RecvStream, tx: mpsc::Sender<nearhand_transport::Result<Control>>) {
    loop {
        let message = match recv_message::<Control>(&mut recv).await {
            Ok(Some(message)) => Ok(message),
            Ok(None) => return,
            Err(e) => Err(e),
        };
        let failed = message.is_err();
        if tx.send(message).await.is_err() || failed {
            return;
        }
    }
}

/// Replace an opaque "connection closed" with the agent's own reason, when it
/// gave one.
fn explain(conn: &Connection, error: anyhow::Error) -> anyhow::Error {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(close)) => {
            let reason = String::from_utf8_lossy(&close.reason);
            anyhow::anyhow!(
                "agent closed the connection: {reason} (code {})",
                close.error_code
            )
        }
        Some(other) => anyhow::anyhow!("connection lost: {other}"),
        None => error,
    }
}

struct Stats {
    datagrams: u64,
    bytes: u64,
    frames: u64,
    keyframes: u64,
    keyframe_requests: u64,
    undecodable: u64,
    simulated_drops: u64,
    window_started: Instant,
    window_frames: u64,
    window_bytes: u64,
}

impl Stats {
    fn new() -> Self {
        Self {
            datagrams: 0,
            bytes: 0,
            frames: 0,
            keyframes: 0,
            keyframe_requests: 0,
            undecodable: 0,
            simulated_drops: 0,
            window_started: Instant::now(),
            window_frames: 0,
            window_bytes: 0,
        }
    }

    fn print_window(&mut self, elapsed: Duration, reassembler: &Reassembler, conn: &Connection) {
        let secs = self.window_started.elapsed().as_secs_f64();
        let bytes = self.bytes - self.window_bytes;
        let r = reassembler.stats();
        println!(
            "{:>5.1}s  {:>5.1} fps  {:>6.2} Mbit/s  delivered {}  incomplete {}  waiting-for-key {}  kf-requests {}  rtt {:.1} ms",
            elapsed.as_secs_f64(),
            self.window_frames as f64 / secs,
            bytes as f64 * 8.0 / 1_000_000.0 / secs,
            r.delivered,
            r.incomplete,
            r.dropped_waiting_for_keyframe,
            self.keyframe_requests,
            conn.rtt().as_secs_f64() * 1000.0,
        );
        self.window_started = Instant::now();
        self.window_frames = 0;
        self.window_bytes = self.bytes;
    }

    fn print_summary(
        &self,
        elapsed: Duration,
        reassembler: &Reassembler,
        record: Option<&std::path::Path>,
    ) {
        let r = reassembler.stats();
        let secs = elapsed.as_secs_f64();
        println!("--- {secs:.1}s ---");
        println!(
            "received:        {} datagrams, {} KiB ({:.2} Mbit/s)",
            self.datagrams,
            self.bytes / 1024,
            self.bytes as f64 * 8.0 / 1_000_000.0 / secs
        );
        println!(
            "frames:          {} delivered ({} keyframes), {:.1} fps",
            self.frames,
            self.keyframes,
            self.frames as f64 / secs
        );
        println!(
            "loss handling:   {} incomplete, {} dropped waiting for a keyframe, {} keyframe requests",
            r.incomplete, r.dropped_waiting_for_keyframe, self.keyframe_requests
        );
        println!(
            "oddities:        {} late, {} duplicate, {} invalid, {} undecodable chunks",
            r.late_chunks, r.duplicate_chunks, r.invalid_chunks, self.undecodable
        );
        if self.simulated_drops > 0 {
            println!(
                "simulated loss:  {} datagrams discarded on purpose",
                self.simulated_drops
            );
        }
        if let Some(path) = record {
            println!("recorded to:     {}", path.display());
        }
    }
}

/// Deterministic-enough random datagram loss, for testing recovery without a
/// lossy network. xorshift, because pulling in a RNG crate for a diagnostic
/// flag is not worth it.
struct LossSimulator {
    percent: u8,
    state: u64,
}

impl LossSimulator {
    fn new(percent: u8) -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Self {
            percent: percent.min(100),
            state: seed | 1,
        }
    }

    fn drop_this(&mut self) -> bool {
        if self.percent == 0 {
            return false;
        }
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        (self.state % 100) < u64::from(self.percent)
    }
}
