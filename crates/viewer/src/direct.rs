//! `nearhand-viewer direct`: connect straight to an agent on the LAN (M0).
//!
//! The network half of the viewer: handshake, video datagrams in, reassembly,
//! keyframe recovery and clock synchronisation, the user's input out on a
//! stream of its own, the host's pointer in on another, and clipboard text
//! both ways. Complete frames go to
//! whoever presents them (the window's decode thread, a `--record` file, or
//! both) and the numbers go to [`Shared`] for the overlay.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nearhand_clipboard::ClipboardSync;
use nearhand_core::clock::ClockSync;
use nearhand_core::proto::close;
use nearhand_core::video::{AssembledFrame, Reassembler, ReassemblyStats, decode_chunk};
use nearhand_core::{
    Caps, Clipboard, Codec, Control, Cursor, Input, Monitor, PROTOCOL_VERSION, StreamKind, wire,
};
use nearhand_transport::{
    Fingerprint, client_endpoint, connect, recv_message, send_all, send_message,
};
use quinn::{Connection, ConnectionError, RecvStream, SendStream};
use tokio::sync::{Notify, mpsc};

/// A frame still missing chunks after this long with no datagrams at all is
/// abandoned. Without it, loss at the end of a burst would go unnoticed until
/// the screen next changes, possibly seconds later.
const PARTIAL_TIMEOUT: Duration = Duration::from_millis(100);

/// Keyframes are expensive; ask at most this often. A keyframe takes an RTT
/// plus an encode to arrive, and asking again sooner only produces two.
const KEYFRAME_REQUEST_INTERVAL: Duration = Duration::from_millis(250);

const TICK: Duration = Duration::from_millis(50);

/// Clock probes: quickly at first so latency figures appear within a second,
/// then gently.
const PING_FAST: Duration = Duration::from_millis(100);
const PING_FAST_FOR: Duration = Duration::from_secs(2);
const PING_SLOW: Duration = Duration::from_secs(1);

/// A complete frame and when the last of it arrived, on the capture clock.
// Read only by the window, which exists only on Windows so far (macOS: M4).
#[cfg_attr(not(windows), allow(dead_code))]
pub struct Received {
    pub frame: AssembledFrame,
    pub received_us: u64,
}

/// What the network side knows, for the overlay.
// Read only by the window, which exists only on Windows so far (macOS: M4).
#[cfg_attr(not(windows), allow(dead_code))]
#[derive(Debug, Default, Clone)]
pub struct NetSnapshot {
    pub fps: f64,
    pub mbps: f64,
    pub rtt_ms: f64,
    /// Agent clock minus viewer clock, and how sure we are of it.
    pub clock_offset_us: Option<i64>,
    pub clock_uncertainty_us: Option<u64>,
    pub reassembly: ReassemblyStats,
    pub keyframe_requests: u64,
    /// The watched monitor's size, once known.
    pub monitor_size: Option<(u32, u32)>,
    /// The host's monitors, and which one is being watched.
    pub monitors: Vec<Monitor>,
    pub watching: u8,
}

/// State shared between the network task and the presenting side.
#[derive(Debug, Default)]
pub struct Shared {
    pub net: Mutex<NetSnapshot>,
    /// Set by the decoder when it cannot use a frame; the network side turns
    /// it into a keyframe request.
    pub keyframe_wanted: AtomicBool,
    /// Tells the network side to say goodbye and stop.
    pub stop: Notify,
}

impl Shared {
    // Read only by the window, which exists only on Windows so far (macOS: M4).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn snapshot(&self) -> NetSnapshot {
        self.net.lock().map(|s| s.clone()).unwrap_or_default()
    }

    fn update(&self, f: impl FnOnce(&mut NetSnapshot)) {
        if let Ok(mut snapshot) = self.net.lock() {
            f(&mut snapshot);
        }
    }
}

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
    /// Where complete frames go for decoding, if anywhere.
    pub frames: Option<std::sync::mpsc::Sender<Received>>,
    /// Keyboard and mouse to send, if anything produces them.
    pub input: Option<mpsc::UnboundedReceiver<Input>>,
    /// Where the host's pointer changes go, if anywhere. Shapes are checked
    /// before they get here.
    pub cursor: Option<Box<dyn Fn(Cursor) + Send + Sync>>,
    /// Keep this machine's clipboard in step with the agent's.
    pub clipboard: bool,
    /// Requests to watch another of the host's monitors, by id.
    pub switch: Option<mpsc::UnboundedReceiver<u8>>,
    pub shared: Arc<Shared>,
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
            let Some(m) = monitors.iter().find(|m| m.id == options.monitor) else {
                bail!(
                    "the agent has no monitor {}; it has {}",
                    options.monitor,
                    monitors.len()
                );
            };
            let size = (u32::from(m.width), u32::from(m.height));
            options.shared.update(|s| {
                s.monitor_size = Some(size);
                s.monitors = monitors.clone();
                s.watching = options.monitor;
            });
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

    let clipboard = if options.clipboard {
        start_clipboard(&conn)
    } else {
        None
    };
    tokio::spawn(accept_streams(conn.clone(), options.cursor, clipboard));

    if let Some(events) = options.input {
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = send_input(&conn, events).await {
                tracing::debug!(error = %e, "input stream ended");
            }
        });
    }

    let mut recording = match &options.record {
        Some(path) => Some(BufWriter::new(
            File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => None,
    };

    let mut switch = options.switch;
    let mut reassembler = Reassembler::new();
    let mut loss = LossSimulator::new(options.simulate_loss);
    let mut stats = Stats::new();
    let started = Instant::now();
    let deadline = options.seconds.map(|s| started + Duration::from_secs(s));
    let mut last_datagram = Instant::now();
    let mut keyframe_needed = false;
    let mut last_keyframe_request: Option<Instant> = None;
    let mut ticker = tokio::time::interval(TICK);
    let mut clock = ClockSync::new();
    let mut last_ping: Option<Instant> = None;
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
                    let received_us = nearhand_capture::clock::now_us();
                    stats.frames += 1;
                    stats.window_frames += 1;
                    if frame.keyframe {
                        stats.keyframes += 1;
                    }
                    if let Some(out) = recording.as_mut() {
                        out.write_all(&frame.data).context("writing the recording")?;
                    }
                    if let Some(sink) = &options.frames
                        && sink.send(Received { frame, received_us }).is_err()
                    {
                        // The window closed.
                        break Ok(());
                    }
                }
            }

            message = control_rx.recv() => match message {
                Some(Ok(Control::Pong { viewer_us, agent_us })) => {
                    clock.add(viewer_us, agent_us, nearhand_capture::clock::now_us());
                    options.shared.update(|s| {
                        s.clock_offset_us = clock.offset_us();
                        s.clock_uncertainty_us = clock.uncertainty_us();
                    });
                }
                Some(Ok(Control::MonitorList(monitors))) => {
                    tracing::info!(count = monitors.len(), "monitor list updated");
                    options.shared.update(|s| s.monitors = monitors);
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
                if options.shared.keyframe_wanted.swap(false, Ordering::Relaxed) {
                    keyframe_needed = true;
                }
                let ping_every = if started.elapsed() < PING_FAST_FOR { PING_FAST } else { PING_SLOW };
                if last_ping.is_none_or(|t| t.elapsed() >= ping_every) {
                    let ping = Control::Ping { viewer_us: nearhand_capture::clock::now_us() };
                    send_message(&mut send, &ping).await?;
                    last_ping = Some(Instant::now());
                }
                if stats.window_started.elapsed() >= Duration::from_secs(1) {
                    let (fps, mbps) = stats.print_window(started.elapsed(), &reassembler, &conn);
                    options.shared.update(|s| {
                        s.fps = fps;
                        s.mbps = mbps;
                        s.rtt_ms = conn.rtt().as_secs_f64() * 1000.0;
                        s.reassembly = reassembler.stats();
                        s.keyframe_requests = stats.keyframe_requests;
                    });
                }
                if deadline.is_some_and(|d| Instant::now() >= d) {
                    break Ok(());
                }
            }

            _ = &mut ctrl_c => break Ok(()),
            _ = options.shared.stop.notified() => break Ok(()),

            Some(monitor) = next_switch(&mut switch) => {
                let known = options.shared.snapshot().monitors.iter().any(|m| m.id == monitor);
                if known {
                    // The agent restarts capture and encoding on the new
                    // monitor, starting with a keyframe whose picture size
                    // the decoder picks up by itself; frame ids carry on.
                    send_message(
                        &mut send,
                        &Control::StartVideo { monitor, codec: Codec::H264, max_fps: options.fps },
                    )
                    .await?;
                    options.shared.update(|s| s.watching = monitor);
                    println!("watching monitor {monitor}");
                }
            }
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

/// Accept the agent's unidirectional streams for as long as the connection
/// lasts.
async fn accept_streams(
    conn: Connection,
    cursor: Option<Box<dyn Fn(Cursor) + Send + Sync>>,
    clipboard: Option<Arc<ClipboardSync>>,
) {
    let cursor: Option<Arc<dyn Fn(Cursor) + Send + Sync>> = cursor.map(Arc::from);
    while let Ok(mut recv) = conn.accept_uni().await {
        match recv_message::<StreamKind>(&mut recv).await {
            Ok(Some(StreamKind::Cursor)) => {
                tokio::spawn(read_cursor(conn.clone(), recv, cursor.clone()));
            }
            Ok(Some(StreamKind::Clipboard)) => {
                tokio::spawn(read_clipboard(conn.clone(), recv, clipboard.clone()));
            }
            Ok(None) => {}
            // Viewer-to-agent only, or unreadable.
            Ok(Some(StreamKind::Input)) | Err(_) => {
                conn.close(close::PROTOCOL.into(), b"unexpected stream");
                return;
            }
        }
    }
}

/// Watch this machine's clipboard and send its changes to the agent, below
/// every other stream in priority.
fn start_clipboard(conn: &Connection) -> Option<Arc<ClipboardSync>> {
    let (tx, rx) = mpsc::unbounded_channel();
    let sync = match ClipboardSync::start(move |text| {
        let _ = tx.send(Clipboard::Text(text));
    }) {
        Ok(sync) => sync,
        Err(e) => {
            tracing::warn!(error = %e, "clipboard sync unavailable");
            return None;
        }
    };
    let conn = conn.clone();
    tokio::spawn(async move {
        if let Err(e) = send_all(&conn, StreamKind::Clipboard, -1, rx).await {
            tracing::debug!(error = %e, "clipboard stream ended");
        }
    });
    Some(Arc::new(sync))
}

/// Put the agent's clipboard text on this machine's clipboard.
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

async fn read_cursor(
    conn: Connection,
    mut recv: RecvStream,
    sink: Option<Arc<dyn Fn(Cursor) + Send + Sync>>,
) {
    loop {
        let change = match recv_message::<Cursor>(&mut recv).await {
            Ok(Some(change)) => change,
            Ok(None) => return,
            Err(e) => {
                if conn.close_reason().is_none() {
                    tracing::info!(error = %e, "malformed cursor message");
                    conn.close(close::PROTOCOL.into(), b"malformed cursor message");
                }
                return;
            }
        };
        // The image goes straight to the OS, so it must be what it claims.
        if let Cursor::Shape(shape) = &change
            && !shape.is_valid()
        {
            conn.close(close::PROTOCOL.into(), b"invalid cursor shape");
            return;
        }
        if let Some(sink) = &sink {
            sink(change);
        }
    }
}

/// The next monitor switch request, or never if nothing can make one.
async fn next_switch(switch: &mut Option<mpsc::UnboundedReceiver<u8>>) -> Option<u8> {
    match switch {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Stream input to the agent until the window stops producing it.
///
/// Whatever has queued up is written in one go, and a mouse move followed by
/// another move is dropped: the pointer only needs to end up in the right
/// place, and a backlog of stale positions would only make it lag.
async fn send_input(
    conn: &Connection,
    mut events: mpsc::UnboundedReceiver<Input>,
) -> nearhand_transport::Result<()> {
    let mut send: SendStream = conn.open_uni().await?;
    // Ahead of every other stream: a key-up stuck behind a clipboard transfer
    // is a stuck key.
    let _ = send.set_priority(i32::MAX);
    send_message(&mut send, &StreamKind::Input).await?;

    let mut batch = Vec::new();
    let mut bytes = Vec::new();
    while let Some(first) = events.recv().await {
        batch.push(first);
        while let Ok(next) = events.try_recv() {
            batch.push(next);
        }
        bytes.clear();
        for (i, event) in batch.iter().enumerate() {
            let superseded = matches!(event, Input::MouseMove { .. })
                && matches!(batch.get(i + 1), Some(Input::MouseMove { .. }));
            if !superseded {
                bytes.extend(wire::encode(event).map_err(nearhand_transport::Error::Protocol)?);
            }
        }
        batch.clear();
        send.write_all(&bytes).await?;
    }
    let _ = send.finish();
    Ok(())
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

    /// Print the last second and return its frame rate and bitrate.
    fn print_window(
        &mut self,
        elapsed: Duration,
        reassembler: &Reassembler,
        conn: &Connection,
    ) -> (f64, f64) {
        let secs = self.window_started.elapsed().as_secs_f64();
        let fps = self.window_frames as f64 / secs;
        let mbps = (self.bytes - self.window_bytes) as f64 * 8.0 / 1_000_000.0 / secs;
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
        (fps, mbps)
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
