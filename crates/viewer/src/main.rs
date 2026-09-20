//! Nearhand viewer — the native controlling app and address book.
//!
//! One GPU path: hardware decode straight into a `wgpu` surface, `egui` for the
//! surrounding UI.

mod direct;
mod known;
#[cfg(windows)]
mod present;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(windows)]
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nearhand_core::rendezvous::DeviceId;
use nearhand_transport::{Fingerprint, rendezvous};

use crate::direct::Shared;

/// How long to wait for the agent's monitor list before giving up.
#[cfg(windows)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(name = "nearhand-viewer", version, about, long_about = None)]
struct Cli {
    /// Verbosity: -v for debug, -vv for trace.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Connect to a device by its ID, through a server.
    ///
    /// Opens a window showing the remote screen and sends it keyboard and
    /// mouse, with a latency overlay (Ctrl+Shift+F1 toggles it).
    /// Ctrl+Shift+F2 switches monitors; Ctrl+Alt+End sends Ctrl+Alt+Del.
    Connect {
        /// The device's ID, as its agent shows it: `123 456 7890`.
        id: DeviceId,
        /// The server's address, for example `203.0.113.10:443`.
        #[arg(long)]
        server: SocketAddr,
        /// The fingerprint the server printed when it started.
        #[arg(long)]
        server_fingerprint: Fingerprint,
        /// The password the agent shows. Asked for if the agent wants one
        /// and it is not given here.
        #[arg(long, conflicts_with = "token")]
        password: Option<String>,
        /// Connect as a user of the server, with an API token of theirs
        /// (`nht_…`): the server hands out a grant for the device if the
        /// user has one. `NEARHAND_TOKEN` in the environment works too, and
        /// stays out of the shell's history.
        #[arg(long)]
        token: Option<String>,
        /// Go through the server's relay even where a direct connection
        /// would work: for testing the relay and measuring what it costs.
        #[arg(long)]
        relay_only: bool,
        /// Connect although the device answers with another key than the
        /// one this viewer saw under that ID before, and remember the new
        /// one. Only when you know why it changed.
        #[arg(long)]
        trust_new_key: bool,
        #[command(flatten)]
        watch: Watch,
    },
    /// Connect straight to an agent's `listen` address, no server.
    Direct {
        /// Agent address, for example `192.168.1.20:4433`.
        address: SocketAddr,
        /// The fingerprint the agent printed when it started.
        #[arg(long)]
        fingerprint: Fingerprint,
        #[command(flatten)]
        watch: Watch,
    },
}

/// How to watch, whichever way the agent was reached.
#[derive(clap::Args, Debug)]
struct Watch {
    /// Which of the agent's monitors to watch.
    #[arg(long, default_value_t = 0)]
    monitor: u8,
    /// Frame-rate cap to ask the agent for.
    #[arg(long, default_value_t = 60)]
    fps: u8,
    /// Disconnect after this many seconds; otherwise run until the window
    /// closes or Ctrl+C.
    #[arg(long)]
    seconds: Option<u64>,
    /// Write the received H.264 stream (Annex B) to this file.
    #[arg(long)]
    record: Option<PathBuf>,
    /// Receive without opening a window.
    #[arg(long)]
    headless: bool,
    /// Diagnostic: discard this percentage of incoming datagrams, to
    /// exercise loss recovery on a network that does not lose any.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
    simulate_loss: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Some(Command::Connect {
            id,
            server,
            server_fingerprint,
            password,
            token,
            relay_only,
            trust_new_key,
            watch,
        }) => {
            let token = token.or_else(|| {
                std::env::var("NEARHAND_TOKEN")
                    .ok()
                    .filter(|t| !t.is_empty() && password.is_none())
            });
            let route = if relay_only {
                rendezvous::Route::RelayOnly
            } else {
                rendezvous::Route::Best
            };
            let target = direct::Target::Server {
                server,
                server_fingerprint,
                id,
                route,
                token,
            };
            watch_target(target, password, watch, trust_new_key)
        }
        Some(Command::Direct {
            address,
            fingerprint,
            watch,
        }) => {
            let target = direct::Target::Direct {
                address,
                fingerprint,
            };
            watch_target(target, None, watch, false)
        }
        // No subcommand opens the address book, which needs a server. [M2]
        None => bail!("not implemented: scheduled for M2, see the roadmap in README.md"),
    }
}

fn watch_target(
    target: direct::Target,
    password: Option<String>,
    watch: Watch,
    trust_new_key: bool,
) -> Result<()> {
    let options = direct::Options {
        target,
        password,
        monitor: watch.monitor,
        fps: watch.fps.max(1),
        seconds: watch.seconds,
        record: watch.record,
        simulate_loss: watch.simulate_loss,
        frames: None,
        input: None,
        cursor: None,
        clipboard: false,
        switch: None,
        shared: Arc::new(Shared::default()),
        trust_new_key,
    };
    if watch.headless {
        let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
        runtime.block_on(direct::run(options))
    } else {
        windowed(options)
    }
}

/// Network on a tokio runtime, decode on its own thread, the window on this
/// one — which Windows requires of the thread that created it.
#[cfg(windows)]
fn windowed(mut options: direct::Options) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    let shared = options.shared.clone();
    // Created before the network starts, so pointer changes arriving from the
    // first moment have somewhere to go.
    let event_loop = present::event_loop()?;
    let proxy = event_loop.create_proxy();
    options.clipboard = true;
    let (switch_tx, switch_rx) = tokio::sync::mpsc::unbounded_channel();
    options.switch = Some(switch_rx);
    options.cursor = Some(Box::new(move |change| {
        let _ = proxy.send_event(present::UserEvent::Cursor(change));
    }));
    let (frames_tx, frames_rx) = std::sync::mpsc::channel();
    options.frames = Some(frames_tx);
    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
    options.input = Some(input_rx);
    let title = format!("Nearhand — {}", options.target);
    // The window owns the deadline, so the network side runs until told.
    let seconds = options.seconds.take();
    let network = runtime.spawn(direct::run(options));

    // The window needs the video size before anything can be created; the
    // agent sends it in its monitor list, straight after the handshake.
    let started = Instant::now();
    let video_size = loop {
        if let Some(size) = shared.snapshot().monitor_size {
            break size;
        }
        if network.is_finished() {
            return runtime
                .block_on(network)
                .context("network task panicked")?
                .context("could not start the session");
        }
        if started.elapsed() > CONNECT_TIMEOUT {
            bail!("no monitor list from the agent within {CONNECT_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    // Slots big enough for any of the host's monitors, so switching between
    // them never has to rebuild the textures shared with the decoder.
    let monitors = shared.snapshot().monitors;
    let slot_size = monitors.iter().fold(video_size, |(w, h), m| {
        (w.max(u32::from(m.width)), h.max(u32::from(m.height)))
    });

    let windowed = present::run(
        event_loop,
        present::Options {
            title,
            video_size,
            slot_size,
            frames: frames_rx,
            shared: shared.clone(),
            input: input_tx,
            switch: switch_tx,
            runtime: runtime.handle().clone(),
            seconds,
        },
    );

    // Window closed: say goodbye, then let the decode thread drain.
    shared.stop.notify_one();
    let network = runtime.block_on(network).context("network task panicked")?;
    let decode = windowed?;
    if let Some(thread) = decode {
        let _ = thread.join();
    }
    network
}

#[cfg(not(windows))]
fn windowed(_options: direct::Options) -> Result<()> {
    bail!("the viewer window needs Windows for now (macOS arrives in M4); use --headless")
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}
