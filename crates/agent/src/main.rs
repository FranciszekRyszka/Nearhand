//! Nearhand agent — runs on the controlled machine.
//!
//! Captures the screen, encodes, injects input. Holds one idle outbound QUIC
//! connection to its server and never listens on a port; see `docs/security.md`.
//!
//! The one exception is `listen`, the M0 test mode: it accepts a viewer
//! directly on the LAN, with no server, so the pipeline can be measured on its
//! own.

mod access;
mod elevation;
mod enroll;
mod gate;
mod grants;
mod host;
mod indicator;
mod input;
mod machine;
mod password;
mod pipeline;
mod portable;
mod prompt;
mod rate;
#[cfg(windows)]
mod service;
mod session;
mod setup;
mod unattended;
mod update;
mod window;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nearhand_core::proto::close;
use nearhand_transport::{Fingerprint, Identity, server_endpoint};
use quinn::Endpoint;
use tokio::sync::Semaphore;

use crate::session::SessionConfig;

#[derive(Parser, Debug)]
#[command(name = "nearhand-agent", version, about, long_about = None)]
struct Cli {
    /// Verbosity: -v for debug, -vv for trace.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Write the log to this file instead of the terminal.
    #[arg(long, global = true)]
    log: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Set this computer up for unattended access, as administrator: its
    /// key and ID, its server, an access password, and the Windows service
    /// that keeps the agent running.
    Install {
        /// The server's address: `desk.example.com`, `desk.example.com:4433`
        /// or `203.0.113.10:443`. The port is 443 unless given.
        #[arg(long)]
        server: String,
        /// The fingerprint the server printed when it started.
        #[arg(long)]
        server_fingerprint: Fingerprint,
        /// The access password. Asked for, without showing it, if not given
        /// here — where it would stay in the shell's history — unless the
        /// machine enrolls with `--token`: then people reach it with grants
        /// from the server, and a password is only a second way in.
        #[arg(long)]
        password: Option<String>,
        /// The most video bitrate to use.
        #[arg(long, default_value_t = machine::DEFAULT_BITRATE_KBPS)]
        bitrate_kbps: u32,
        /// An enrollment token from the server's administrator, to join its
        /// managed devices: users the server grants access reach it without
        /// the access password.
        #[arg(long)]
        token: Option<String>,
        /// The name to enroll this computer under; its computer name if not
        /// given.
        #[arg(long, requires = "token")]
        name: Option<String>,
        /// Ask for the access password *as well as* a grant, rather than
        /// instead of one: then a server that was taken over cannot open
        /// this computer on its own, because it does not know the
        /// password. Needs --token and a password.
        #[arg(long, requires = "token")]
        password_with_grant: bool,
    },
    /// `install` without the service, which the MSI registers itself.
    #[command(hide = true)]
    Configure {
        #[arg(long)]
        server: String,
        #[arg(long)]
        server_fingerprint: Fingerprint,
        #[arg(long)]
        password: Option<String>,
        #[arg(long, default_value_t = machine::DEFAULT_BITRATE_KBPS)]
        bitrate_kbps: u32,
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        password_with_grant: bool,
    },
    /// Remove the service, as administrator.
    Uninstall {
        /// Also delete the key and configuration. The next install gets a
        /// new ID.
        #[arg(long)]
        purge: bool,
    },
    /// Change the access password, as administrator.
    SetPassword {
        /// The new password; asked for if not given.
        #[arg(long)]
        password: Option<String>,
        /// Remove the password instead: only grants from the server let
        /// anyone in.
        #[arg(long, conflicts_with = "password")]
        none: bool,
        /// From now on, ask for this password as well as a grant from the
        /// server, rather than instead of one.
        #[arg(long, conflicts_with = "none")]
        with_grant: bool,
        /// From now on, let either the password or a grant in on its own.
        #[arg(long, conflicts_with_all = ["none", "with_grant"])]
        either: bool,
    },
    /// Show whether the service runs, and this computer's ID.
    Status,
    /// Run the installed agent in the foreground. The service runs this
    /// in the console session; run it by hand, as administrator, to watch.
    Run {
        /// How the service asks it to stop.
        #[arg(long, hide = true)]
        stop_event: Option<String>,
        /// Another folder than the installed one, for testing.
        #[arg(long, hide = true)]
        dir: Option<PathBuf>,
    },
    /// Entry point for the Windows service manager.
    #[command(hide = true)]
    Service,
    /// Portable quick-support mode: register with a server and show an ID
    /// and one-time password for the viewer to use.
    Portable {
        /// The server's address, for example `203.0.113.10:443`.
        #[arg(long)]
        server: SocketAddr,
        /// The fingerprint the server printed when it started.
        #[arg(long)]
        server_fingerprint: Fingerprint,
        /// This device's key, created on first use. It is the device's
        /// identity: its ID is derived from it.
        #[arg(long, default_value_os_t = portable::default_key_path())]
        key: PathBuf,
        /// The most video bitrate to use.
        #[arg(long, default_value_t = 10_000)]
        bitrate_kbps: u32,
        /// No window: print the ID and password here instead. Then no one
        /// is asked to allow a session — the password alone lets a viewer in
        /// — and sessions are announced here.
        #[arg(long)]
        console: bool,
    },
    /// M0 only: accept a viewer directly on the LAN, no server.
    ///
    /// Prints a certificate fingerprint to give to the viewer. The viewer
    /// chooses which monitor to watch.
    Listen {
        /// Address and UDP port to listen on. Use 127.0.0.1 to test on one
        /// machine without opening the firewall.
        #[arg(long, default_value = "0.0.0.0:4433")]
        bind: SocketAddr,
        /// Starting video bitrate; the viewer can change it.
        #[arg(long, default_value_t = 10_000)]
        bitrate_kbps: u32,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose, cli.log.as_deref());
    dpi_aware();

    match cli.command {
        Command::Listen { bind, bitrate_kbps } => {
            let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
            let config = SessionConfig {
                bitrate_kbps,
                gate: None,
                grants: None,
                host: None,
                password_with_grant: false,
            };
            runtime.block_on(listen(bind, config))
        }
        Command::Portable {
            server,
            server_fingerprint,
            key,
            bitrate_kbps,
            console,
        } => portable::run(portable::Options {
            server,
            server_fingerprint,
            key,
            bitrate_kbps,
            window: !console,
        }),
        Command::Install {
            server,
            server_fingerprint,
            password,
            bitrate_kbps,
            token,
            name,
            password_with_grant,
        } => setup::install(setup::Install {
            server,
            server_fingerprint,
            password,
            bitrate_kbps,
            token,
            name,
            password_with_grant,
        }),
        Command::Configure {
            server,
            server_fingerprint,
            password,
            bitrate_kbps,
            token,
            name,
            password_with_grant,
        } => setup::configure(setup::Install {
            server,
            server_fingerprint,
            password,
            bitrate_kbps,
            token,
            name,
            password_with_grant,
        })
        .map(|identity| {
            println!(
                "Configured. This computer's ID is {}.",
                identity.device_id()
            )
        }),
        Command::Uninstall { purge } => setup::uninstall(purge),
        Command::SetPassword {
            password,
            none,
            with_grant,
            either,
        } => setup::set_password(
            password,
            none,
            match (with_grant, either) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            },
        ),
        Command::Status => setup::status(),
        Command::Run { stop_event, dir } => {
            unattended::run(dir.unwrap_or_else(machine::dir), stop_event)
        }
        #[cfg(windows)]
        Command::Service => service::dispatch(),
        #[cfg(not(windows))]
        Command::Service => anyhow::bail!("the service is Windows-only"),
    }
}

async fn listen(bind: SocketAddr, config: SessionConfig) -> Result<()> {
    let identity = Identity::generate()?;
    let endpoint =
        server_endpoint(bind, &identity).with_context(|| format!("listening on {bind}"))?;
    let local = endpoint.local_addr()?;

    // Printed rather than logged: this is the one thing the user must copy.
    println!("nearhand agent listening on {local}");
    println!("fingerprint: {}", identity.fingerprint());
    println!(
        "connect with: nearhand-viewer direct {local} --fingerprint {}",
        identity.fingerprint()
    );

    tokio::select! {
        () = accept_viewers(endpoint.clone(), Arc::new(config), one_viewer()) => {}
        _ = tokio::signal::ctrl_c() => println!("stopping"),
    }
    endpoint.close(close::NORMAL.into(), b"agent stopping");
    endpoint.wait_idle().await;
    Ok(())
}

/// Serve viewers connecting to `endpoint`, one at a time, until it closes.
/// The slot a viewer holds for its session. One at a time: two would fight
/// over the display duplication and the hardware encoder.
fn one_viewer() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(1))
}

/// How long a viewer has to open its control stream once connected.
const FIRST_STREAM: std::time::Duration = std::time::Duration::from_secs(15);

/// Serve viewers arriving at `endpoint`, each once it holds `slot`. Endpoints
/// sharing a slot share the limit.
async fn accept_viewers(endpoint: Endpoint, config: Arc<SessionConfig>, slot: Arc<Semaphore>) {
    while let Some(incoming) = endpoint.accept().await {
        let config = config.clone();
        let slot = slot.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::info!(error = %e, "handshake failed");
                    return;
                }
            };
            let remote = conn.remote_address();
            // A viewer may reach this agent two ways at once — directly and
            // through the relay — and keep one: the one it opens its control
            // stream on. Only that one may take the slot; the other is closed
            // by the viewer, unused.
            let control = match tokio::time::timeout(FIRST_STREAM, conn.accept_bi()).await {
                Ok(Ok(control)) => control,
                _ => {
                    tracing::debug!(%remote, "connection not used by its viewer");
                    return;
                }
            };
            let Ok(_permit) = slot.try_acquire_owned() else {
                tracing::info!(%remote, "turned away: a viewer is already connected");
                conn.close(close::BUSY.into(), b"another viewer is connected");
                return;
            };

            let path = nearhand_transport::rendezvous::path_of(remote);
            tracing::info!(%remote, %path, "viewer connected");
            match session::serve(conn, control, &config).await {
                Ok(()) => tracing::info!(%remote, "viewer left"),
                Err(e) => tracing::info!(%remote, error = %format!("{e:#}"), "session ended"),
            }
        });
    }
}

/// Work in physical pixels. Without this, Windows scales coordinates for a
/// DPI-unaware process, and injected mouse positions would miss on any display
/// not at 100%.
#[cfg(windows)]
fn dpi_aware() {
    use windows::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
    };
    if let Err(e) =
        unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) }
    {
        tracing::warn!(error = %e, "could not declare DPI awareness; pointer positions may be off");
    }
}

#[cfg(not(windows))]
fn dpi_aware() {}

fn init_tracing(verbose: u8, log: Option<&Path>) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    // The quick-support window's graphics stack describes every adapter it
    // finds at info level; only its warnings matter unless asked for more.
    let quiet = if verbose == 0 {
        tracing::Level::WARN
    } else {
        level
    };
    let filter = tracing_subscriber::filter::Targets::new()
        .with_default(level)
        .with_target("wgpu_core", quiet)
        .with_target("wgpu_hal", quiet)
        .with_target("egui_wgpu", quiet)
        .with_target("naga", quiet);
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    let registry = tracing_subscriber::registry().with(filter);
    match log.map(open_log) {
        Some(Ok(file)) => registry
            .with(
                tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(std::sync::Mutex::new(file)),
            )
            .init(),
        other => {
            registry.with(tracing_subscriber::fmt::layer()).init();
            if let Some(Err(e)) = other {
                tracing::warn!(error = %format!("{e:#}"), "cannot write the log file; logging here");
            }
        }
    }
    // A panic aborts the process, and the agent the service starts has no
    // console to say why: the log is where anyone will look.
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(%info, %backtrace, "panicked");
        report(info);
    }));
}

/// Past this, a log starts over rather than grow without end.
const LOG_LIMIT: u64 = 10 * 1024 * 1024;

fn open_log(path: &Path) -> Result<std::fs::File> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let long = std::fs::metadata(path).is_ok_and(|m| m.len() > LOG_LIMIT);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .append(!long)
        .truncate(long)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    Ok(file)
}
