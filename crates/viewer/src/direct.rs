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
use nearhand_core::access;
use nearhand_core::clock::ClockSync;
use nearhand_core::proto::close;
use nearhand_core::rendezvous::DeviceId;
use nearhand_core::video::{AssembledFrame, Reassembler, ReassemblyStats, Timing, decode_chunk};
use nearhand_core::{
    Caps, Clipboard, Codec, Control, Cursor, Input, Monitor, PROTOCOL_VERSION, StreamKind, wire,
};
use nearhand_transport::{
    Fingerprint, client_endpoint, connect, recv_message, rendezvous, send_all, send_message,
};
use quinn::{Connection, ConnectionError, RecvStream, SendStream};

use crate::known;
use tokio::sync::{Notify, mpsc};

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

/// Which agent to reach, and how.
#[derive(Debug, Clone)]
pub enum Target {
    /// Straight to an address, pinned to a fingerprint copied by hand.
    Direct {
        address: SocketAddr,
        fingerprint: Fingerprint,
    },
    /// By device ID, introduced by a server.
    Server {
        server: SocketAddr,
        server_fingerprint: Fingerprint,
        id: DeviceId,
        route: rendezvous::Route,
        /// An API token of a user of the server, to connect with a grant.
        token: Option<String>,
    },
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Direct { address, .. } => write!(f, "{address}"),
            Target::Server { id, .. } => write!(f, "{id}"),
        }
    }
}

pub struct Options {
    pub target: Target,
    /// For an agent that asks for one; asked for on the terminal if needed
    /// and not given.
    pub password: Option<String>,
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
    pub cursor: Option<Arc<dyn Fn(Cursor) + Send + Sync>>,
    /// Keep this machine's clipboard in step with the agent's.
    pub clipboard: bool,
    /// Requests to watch another of the host's monitors, by id.
    pub switch: Option<mpsc::UnboundedReceiver<u8>>,
    pub shared: Arc<Shared>,
    /// Take a device's key even where it is not the one this viewer saw
    /// last time under that ID (`known`).
    pub trust_new_key: bool,
}

/// How long to keep trying to get back to an agent that went away. The
/// service moving an agent to the session someone just signed in to takes
/// seconds; a restart of the service, a few more.
const RECONNECT_FOR: Duration = Duration::from_secs(120);
const RECONNECT_FIRST: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(10);

/// An error that trying again will not fix: the agent or the person at it
/// decided, or the two ends do not fit. A lost connection is not one of
/// these, and is tried again.
#[derive(Debug)]
struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

fn refusal(text: impl Into<String>) -> anyhow::Error {
    Refusal(text.into()).into()
}

/// What outlives one session and carries into the next.
struct Carried {
    input: Option<Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Input>>>>,
    recording: Option<BufWriter<File>>,
    /// When `--seconds` runs out, across every session.
    deadline: Option<Instant>,
    /// This attempt got as far as the picture. A loss after that is worth
    /// coming back from; a failure before it is reported as it is.
    reached: bool,
}

/// Watch the target until told to stop: across agent restarts, not only
/// for one connection. An installed agent that goes away saying it may be
/// back — the service moving it to a new session, or restarting — is reached
/// again, and so is one whose connection was lost; anything the agent or
/// its person decided is final.
pub async fn run(mut options: Options) -> Result<()> {
    let recording = match &options.record {
        Some(path) => Some(BufWriter::new(
            File::create(path).with_context(|| format!("creating {}", path.display()))?,
        )),
        None => None,
    };
    let mut carried = Carried {
        input: options
            .input
            .take()
            .map(|input| Arc::new(tokio::sync::Mutex::new(input))),
        recording,
        deadline: options
            .seconds
            .map(|s| Instant::now() + Duration::from_secs(s)),
        reached: false,
    };
    let mut established = false;
    let mut lost_at: Option<Instant> = None;
    let mut wait = RECONNECT_FIRST;
    let outcome = loop {
        let attempt = session(&mut options, &mut carried).await;
        if std::mem::take(&mut carried.reached) {
            established = true;
            lost_at = None;
            wait = RECONNECT_FIRST;
        }
        let error = match attempt {
            Ok(()) => break Ok(()),
            // Before any session got going, say what is wrong rather than
            // keep a person waiting to hear it.
            Err(e) if !established => break Err(e),
            Err(e) if e.downcast_ref::<Refusal>().is_some() => break Err(e),
            Err(e) => e,
        };
        let since = *lost_at.get_or_insert_with(Instant::now);
        if since.elapsed() >= RECONNECT_FOR {
            break Err(error.context(format!(
                "could not get back to {} within {RECONNECT_FOR:?}",
                options.target
            )));
        }
        println!(
            "lost {} ({error:#}); trying again in {wait:?}…",
            options.target
        );
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = options.shared.stop.notified() => break Ok(()),
            _ = tokio::signal::ctrl_c() => break Ok(()),
        }
        if carried.deadline.is_some_and(|d| Instant::now() >= d) {
            break Ok(());
        }
        wait = (wait * 2).min(RECONNECT_MAX);
    };
    if let Some(mut out) = carried.recording.take() {
        out.flush().context("flushing the recording")?;
    }
    outcome
}

/// One connection to the agent, from the introduction to its end.
async fn session(options: &mut Options, carried: &mut Carried) -> Result<()> {
    let (endpoint, conn, grant) = match &options.target {
        Target::Direct {
            address,
            fingerprint,
        } => {
            let endpoint = client_endpoint(*address)?;
            let conn = connect(&endpoint, *address, *fingerprint)
                .await
                .with_context(|| format!("connecting to {address}"))?;
            (endpoint, conn, None)
        }
        Target::Server {
            server,
            server_fingerprint,
            id,
            route,
            token,
        } => {
            let endpoint = client_endpoint(*server)?;
            let (conn, grant) = match token {
                Some(token) => {
                    let (conn, grant) = rendezvous::find_granted(
                        &endpoint,
                        *server,
                        *server_fingerprint,
                        *id,
                        *route,
                        token,
                    )
                    .await
                    .with_context(|| format!("reaching {id} through {server}"))?;
                    (conn, Some(grant))
                }
                None => (
                    rendezvous::find(&endpoint, *server, *server_fingerprint, *id, *route)
                        .await
                        .with_context(|| format!("reaching {id} through {server}"))?,
                    None,
                ),
            };
            // The server said which key this device has; this is the
            // key that answered. Whether it is the one it had last time
            // is for `known` to say.
            remember(*id, &conn, options.trust_new_key)?;
            (endpoint, conn, grant)
        }
    };
    if let Some(Ok(claims)) = grant.as_ref().map(|g| g.claims()) {
        println!("granted: {} as {}", claims.role, claims.user);
    }
    let path = rendezvous::path_of(conn.remote_address());
    println!(
        "connected to {} at {}, {path} (rtt {:?})",
        options.target,
        conn.remote_address(),
        conn.rtt()
    );

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
            return Err(refusal(format!(
                "the agent speaks protocol {version}, this viewer {PROTOCOL_VERSION}"
            )));
        }
        Ok(other) => bail!("expected Hello, got {other:?}"),
        Err(e) => return Err(explain(&conn, e.into())),
    };
    let mut next = recv_message::<Control>(&mut recv).await;
    if let Ok(Some(Control::AuthRequired { required })) = next {
        match grant {
            Some(grant) => {
                if !required.takes_grants() {
                    return Err(refusal(
                        "this device takes a password, not a grant from a server",
                    ));
                }
                send_message(&mut send, &Control::Present { grant }).await?;
                // Where a machine asks for both, the grant is only half of
                // it: its password follows (`docs/security.md`).
                if let Some(secret) = required
                    .secret()
                    .filter(|_| required.password_after_grant())
                {
                    println!("this device asks for its access password as well as a grant");
                    let typed = match options.password.clone() {
                        Some(password) => password,
                        None => ask_password().await?,
                    };
                    // Kept for coming back after a loss, so nobody is asked
                    // again for what they typed a minute ago.
                    options.password = Some(typed.clone());
                    prove(&conn, &mut send, &mut recv, secret, &typed).await?;
                }
            }
            None => {
                let secret = required.secret().filter(|_| required.password_is_enough());
                let Some(secret) = secret else {
                    return Err(refusal(format!(
                        "this device needs a grant from its server{}; sign in to it first",
                        if required.secret().is_some() {
                            " as well as its password"
                        } else {
                            ""
                        }
                    )));
                };
                let typed = match options.password.clone() {
                    Some(password) => password,
                    None => ask_password().await?,
                };
                options.password = Some(typed.clone());
                prove(&conn, &mut send, &mut recv, secret, &typed).await?;
            }
        }
        next = recv_message::<Control>(&mut recv).await;
    }
    if let Ok(Some(Control::AwaitingApproval)) = next {
        println!("waiting for the person at the device to allow the session…");
        next = recv_message::<Control>(&mut recv).await;
    }
    match next.map_err(|e| explain(&conn, e.into()))? {
        Some(Control::MonitorList(monitors)) => {
            let Some(m) = monitors.iter().find(|m| m.id == options.monitor) else {
                return Err(refusal(format!(
                    "the agent has no monitor {}; it has {}",
                    options.monitor,
                    monitors.len()
                )));
            };
            // In: a loss from here on is worth coming back from.
            carried.reached = true;
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
        return Err(refusal(format!(
            "the agent offers no H.264 encoder ({:?})",
            agent_caps.codecs
        )));
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
    tokio::spawn(accept_streams(
        conn.clone(),
        options.cursor.clone(),
        clipboard,
    ));

    if let Some(events) = carried.input.clone() {
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = send_input(&conn, &events).await {
                tracing::debug!(error = %e, "input stream ended");
            }
        });
    }

    let recording = &mut carried.recording;
    let mut reassembler = Reassembler::new();
    let mut loss = LossSimulator::new(options.simulate_loss);
    let mut stats = Stats::new();
    let started = Instant::now();
    let deadline = carried.deadline;
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
        // Wake exactly when a repair falls due rather than on the next tick:
        // a frame's lost last chunk would otherwise wait for the next frame.
        let repair_at = reassembler
            .next_deadline(&repair_timing(conn.rtt()))
            .map(|at_us| {
                let now_us = nearhand_capture::clock::now_us();
                // At least a millisecond away, so a deadline that turns out to
                // need nothing done can never spin the loop.
                let wait_us = at_us.saturating_sub(now_us).max(1_000);
                tokio::time::Instant::now() + Duration::from_micros(wait_us)
            });
        tokio::select! {
            datagram = conn.read_datagram() => {
                let datagram = match datagram {
                    Ok(datagram) => datagram,
                    Err(e) => break ended(&conn, e.into()),
                };
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
                let now_us = nearhand_capture::clock::now_us();
                reassembler.push(chunk, now_us);
                if !deliver(&mut reassembler, &mut stats, recording, &options.frames)? {
                    break Ok(()); // The window closed.
                }
                // Straight away rather than on the next tick: every
                // millisecond here is a millisecond the frames behind it wait.
                ask_for_repairs(&mut reassembler, now_us, &conn, &mut send).await?;
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
                Some(Err(e)) => break ended(&conn, e.into()),
                // The agent closed its side of the control stream.
                None => break Ok(()),
            },

            _ = sleep_until(repair_at), if repair_at.is_some() => {
                let now_us = nearhand_capture::clock::now_us();
                ask_for_repairs(&mut reassembler, now_us, &conn, &mut send).await?;
                reassembler.expire(now_us, &repair_timing(conn.rtt()));
                if !deliver(&mut reassembler, &mut stats, recording, &options.frames)? {
                    break Ok(());
                }
            }

            _ = ticker.tick() => {
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

            Some(monitor) = next_switch(&mut options.switch) => {
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
    endpoint.wait_idle().await;

    stats.print_summary(started.elapsed(), &reassembler, options.record.as_deref());
    outcome
}

async fn sleep_until(at: Option<tokio::time::Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Repair timings for the current round trip. A repair takes one round trip
/// plus the agent's turnaround; giving up allows for the request or the
/// repair itself being lost once.
fn repair_timing(rtt: Duration) -> Timing {
    let rtt_us = rtt.as_micros() as u64;
    Timing {
        quiet_us: rtt_us + 5_000,
        retry_us: rtt_us * 3 / 2 + 10_000,
        give_up_us: rtt_us * 3 + 60_000,
    }
}

async fn ask_for_repairs(
    reassembler: &mut Reassembler,
    now_us: u64,
    conn: &Connection,
    send: &mut SendStream,
) -> Result<()> {
    for missing in reassembler.nacks(now_us, &repair_timing(conn.rtt())) {
        let nack = Control::Nack {
            frame_id: missing.frame_id,
            chunks: missing.chunks,
        };
        send_message(send, &nack).await?;
    }
    Ok(())
}

/// Hand every frame the reassembler has ready to the recording and the
/// decoder. False once the decoder side has gone.
fn deliver(
    reassembler: &mut Reassembler,
    stats: &mut Stats,
    recording: &mut Option<BufWriter<File>>,
    frames: &Option<std::sync::mpsc::Sender<Received>>,
) -> Result<bool> {
    while let Some(frame) = reassembler.pop() {
        let received_us = nearhand_capture::clock::now_us();
        stats.frames += 1;
        stats.window_frames += 1;
        if frame.keyframe {
            stats.keyframes += 1;
        }
        if let Some(out) = recording.as_mut() {
            out.write_all(&frame.data)
                .context("writing the recording")?;
        }
        if let Some(sink) = frames
            && sink.send(Received { frame, received_us }).is_err()
        {
            return Ok(false);
        }
    }
    Ok(true)
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
    cursor: Option<Arc<dyn Fn(Cursor) + Send + Sync>>,
    clipboard: Option<Arc<ClipboardSync>>,
) {
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

async fn ask_password() -> Result<String> {
    tokio::task::spawn_blocking(|| {
        use std::io::Write as _;
        print!("password: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim().to_owned())
    })
    .await
    .context("reading the password")?
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
    events: &tokio::sync::Mutex<mpsc::UnboundedReceiver<Input>>,
) -> nearhand_transport::Result<()> {
    // Held for this session only: the next one takes it over when this
    // connection is gone, which is why the loop below also watches for that.
    let mut events = events.lock().await;
    let mut send: SendStream = conn.open_uni().await?;
    // Ahead of every other stream: a key-up stuck behind a clipboard transfer
    // is a stuck key.
    let _ = send.set_priority(i32::MAX);
    send_message(&mut send, &StreamKind::Input).await?;

    let mut batch = Vec::new();
    let mut bytes = Vec::new();
    loop {
        let first = tokio::select! {
            first = events.recv() => first,
            _ = conn.closed() => None,
        };
        let Some(first) = first else { break };
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
/// Prove the password to the agent without sending it, and make it prove
/// the password back (`nearhand_core::access`). Whoever introduced the two
/// of us cannot do either, so if this works there is nobody in between.
async fn prove(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    secret: &access::Secret,
    typed: &str,
) -> Result<()> {
    let binding = nearhand_transport::access::binding(conn)
        .context("this connection carries no password exchange")?;
    let seed = nearhand_transport::access::seed()?;
    // An access password is stretched the slow way the agent stored it:
    // hundreds of milliseconds, off the runtime's threads.
    let material = {
        let secret = secret.clone();
        let typed = typed.to_owned();
        tokio::task::spawn_blocking(move || secret.material(&typed)).await??
    };
    let (viewer, start) = access::Viewer::start(&material, &binding, seed);
    send_message(send, &Control::AuthStart { pake: start }).await?;
    let answer = match recv_message::<Control>(recv)
        .await
        .map_err(|e| explain(conn, e.into()))?
    {
        Some(Control::AuthAnswer { pake }) => pake,
        other => bail!("expected the agent's half of the password exchange, got {other:?}"),
    };
    let (viewer, proof) = viewer.prove(&answer)?;
    send_message(
        send,
        &Control::AuthProve {
            proof: proof.to_vec(),
        },
    )
    .await?;
    match recv_message::<Control>(recv)
        .await
        .map_err(|e| explain(conn, e.into()))?
    {
        // Wrong, and the agent has closed by now; right, and this is what
        // says the agent is the agent.
        Some(Control::AuthProved { proof }) => viewer.check(&proof).context(
            "the agent cannot prove it knows the password:              something is standing between this viewer and the device",
        )?,
        other => bail!("expected the agent's proof, got {other:?}"),
    }
    Ok(())
}

/// Hold a server to what it said before: the key a device answered with
/// must be the key it answered with last time. A grant proves the server's
/// say-so, not the device's, so without this a server that was taken over
/// could put itself in the middle of a session opened with one
/// (`docs/security.md`).
fn remember(id: DeviceId, conn: &Connection, trust_new_key: bool) -> Result<()> {
    let Some(fingerprint) = nearhand_transport::peer_fingerprint(conn) else {
        bail!("the device sent no certificate");
    };
    let mut known = known::Known::load();
    match known.check(id, fingerprint) {
        known::Continuity::Same => return Ok(()),
        known::Continuity::First => {
            println!("first time with {id}: its key is {fingerprint}");
        }
        known::Continuity::Changed { known: before } if !trust_new_key => {
            conn.close(close::PROTOCOL.into(), b"another key than last time");
            // Final: coming back would only meet the same key again.
            return Err(refusal(format!(
                "{id} answered with another key than last time.\n\
                 \n\
                 was:  {before}\n\
                 now:  {fingerprint}\n\
                 \n\
                 A device's ID is made from its key, so this is not a \
                 reinstall — that would change the ID too. Either the \
                 server introduced another machine, or something is \
                 standing between this viewer and the device. Check with \
                 whoever runs the device before going on; --trust-new-key \
                 takes the new key and remembers it instead."
            )));
        }
        known::Continuity::Changed { known: before } => {
            println!("{id} has a new key: {before} → {fingerprint}");
        }
    }
    if let Err(e) = known.remember(id, fingerprint) {
        // Worth saying, not worth refusing the session over.
        tracing::warn!(error = %format!("{e:#}"), "could not write the known devices");
    }
    Ok(())
}

/// Why the connection is over, in words — and whether trying again could
/// help. An agent that closed with a reason decided something, and that is
/// a [`Refusal`], except for [`close::GOING_AWAY`], which says it may be
/// back. A connection lost without a word may be back too.
fn explain(conn: &Connection, error: anyhow::Error) -> anyhow::Error {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(closed)) => {
            let reason = String::from_utf8_lossy(&closed.reason);
            let text = format!(
                "agent closed the connection: {reason} (code {})",
                closed.error_code
            );
            if u64::from(closed.error_code) == u64::from(close::GOING_AWAY) {
                anyhow::anyhow!(text)
            } else {
                refusal(text)
            }
        }
        Some(other) => anyhow::anyhow!("connection lost: {other}"),
        None => error,
    }
}

/// The end of a session's connection: a goodbye from either side is the
/// session over, and anything else is for [`explain`] to name.
fn ended(conn: &Connection, error: anyhow::Error) -> Result<()> {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(closed))
            if u64::from(closed.error_code) == u64::from(close::NORMAL) =>
        {
            let reason = String::from_utf8_lossy(&closed.reason);
            println!("the agent ended the session: {reason}");
            Ok(())
        }
        Some(ConnectionError::LocallyClosed) => Ok(()),
        _ => Err(explain(conn, error)),
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
            "{:>5.1}s  {:>5.1} fps  {:>6.2} Mbit/s  delivered {}  repaired {}  incomplete {}  waiting-for-key {}  kf-requests {}  rtt {:.1} ms",
            elapsed.as_secs_f64(),
            self.window_frames as f64 / secs,
            bytes as f64 * 8.0 / 1_000_000.0 / secs,
            r.delivered,
            r.repaired,
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
            "loss handling:   {} repaired ({} repair requests), {} incomplete, {} dropped waiting for a keyframe, {} keyframe requests",
            r.repaired,
            r.nacks,
            r.incomplete,
            r.dropped_waiting_for_keyframe,
            self.keyframe_requests
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

#[cfg(test)]
mod tests {
    use super::*;
    use nearhand_transport::{Identity, server_endpoint};
    use std::sync::atomic::AtomicUsize;

    /// How a stand-in agent ends each connection it takes, in turn.
    #[derive(Clone, Copy)]
    enum Ending {
        /// As the service does when it moves the agent: it may be back.
        GoingAway,
        /// A decision: nothing to come back for.
        Refused,
        /// Goodbye.
        Bye,
        /// Going away before the viewer ever saw a picture.
        GoingAwayEarly,
    }

    /// An agent that takes a viewer as far as the picture, then ends as
    /// `endings` says, one per connection; how many connections it took.
    fn stand_in(endings: Vec<Ending>) -> (SocketAddr, Fingerprint, Arc<AtomicUsize>) {
        let identity = Identity::generate().expect("identity");
        let fingerprint = identity.fingerprint();
        let endpoint =
            server_endpoint(([127, 0, 0, 1], 0).into(), &identity).expect("agent endpoint");
        let address = endpoint.local_addr().expect("address");
        let taken = Arc::new(AtomicUsize::new(0));
        let count = taken.clone();
        tokio::spawn(async move {
            for ending in endings {
                let Some(incoming) = endpoint.accept().await else {
                    return;
                };
                let conn = incoming.await.expect("handshake");
                count.fetch_add(1, Ordering::Relaxed);
                let (mut send, mut recv) = conn.accept_bi().await.expect("control");
                let _: Option<Control> = recv_message(&mut recv).await.expect("hello");
                let caps = Caps {
                    codecs: vec![Codec::H264],
                    max_width: 1920,
                    max_height: 1080,
                    max_fps: 60,
                };
                send_message(
                    &mut send,
                    &Control::Hello {
                        version: PROTOCOL_VERSION,
                        caps,
                    },
                )
                .await
                .expect("hello");
                if let Ending::GoingAwayEarly = ending {
                    conn.close(close::GOING_AWAY.into(), b"agent stopping");
                    continue;
                }
                let monitor = Monitor {
                    id: 0,
                    width: 1920,
                    height: 1080,
                    x: 0,
                    y: 0,
                    primary: true,
                };
                send_message(&mut send, &Control::MonitorList(vec![monitor]))
                    .await
                    .expect("monitors");
                // The viewer asks for video: it is in.
                let _: Option<Control> = recv_message(&mut recv).await.expect("start video");
                let (code, reason): (u32, &[u8]) = match ending {
                    Ending::GoingAway => (close::GOING_AWAY, b"agent stopping"),
                    Ending::Refused => (close::ENDED_BY_HOST, b"ended at the host"),
                    Ending::Bye | Ending::GoingAwayEarly => (close::NORMAL, b"bye"),
                };
                conn.close(code.into(), reason);
            }
            // Hold the endpoint a moment, so the last close reaches the viewer.
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        (address, fingerprint, taken)
    }

    fn options(address: SocketAddr, fingerprint: Fingerprint) -> Options {
        Options {
            target: Target::Direct {
                address,
                fingerprint,
            },
            password: None,
            monitor: 0,
            fps: 30,
            // A guard: a test that should end by itself does, or fails here.
            seconds: Some(30),
            record: None,
            simulate_loss: 0,
            frames: None,
            input: None,
            cursor: None,
            clipboard: false,
            switch: None,
            shared: Arc::new(Shared::default()),
            trust_new_key: false,
        }
    }

    /// The service moves an agent to the session someone signed in to: the
    /// viewer comes back to the new one by itself.
    #[tokio::test]
    async fn a_viewer_comes_back_to_an_agent_that_went_away() {
        let (address, fingerprint, taken) = stand_in(vec![Ending::GoingAway, Ending::Bye]);
        let outcome =
            tokio::time::timeout(Duration::from_secs(20), run(options(address, fingerprint)))
                .await
                .expect("the viewer finishes");
        outcome.expect("a goodbye ends it cleanly");
        assert_eq!(
            taken.load(Ordering::Relaxed),
            2,
            "connected, lost, connected again"
        );
    }

    /// What the agent or its person decided is final: no coming back.
    #[tokio::test]
    async fn a_viewer_does_not_come_back_to_a_refusal() {
        let (address, fingerprint, taken) = stand_in(vec![Ending::Refused, Ending::Bye]);
        let outcome =
            tokio::time::timeout(Duration::from_secs(20), run(options(address, fingerprint)))
                .await
                .expect("the viewer finishes");
        let error = outcome.expect_err("a refusal is an error");
        assert!(
            format!("{error:#}").contains("ended at the host"),
            "{error:#}"
        );
        assert_eq!(taken.load(Ordering::Relaxed), 1, "it did not try again");
    }

    /// Nothing to come back from before a session got going: an agent
    /// that goes away before the first picture is reported at once, though
    /// the same words later in a session would bring the viewer back.
    #[tokio::test]
    async fn a_first_connection_that_fails_is_not_retried() {
        let (address, fingerprint, taken) = stand_in(vec![Ending::GoingAwayEarly, Ending::Bye]);
        let outcome =
            tokio::time::timeout(Duration::from_secs(20), run(options(address, fingerprint)))
                .await
                .expect("the viewer finishes");
        assert!(outcome.is_err(), "it never got in");
        assert_eq!(taken.load(Ordering::Relaxed), 1, "it did not try again");
    }
}
