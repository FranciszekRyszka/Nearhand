//! Nearhand agent — runs on the controlled machine.
//!
//! Captures the screen, encodes, injects input. Holds one idle outbound QUIC
//! connection to its server and never listens on a port; see `docs/security.md`.
//!
//! The one exception is `listen`, the M0 test mode: it accepts a viewer
//! directly on the LAN, with no server, so the pipeline can be measured on its
//! own.

mod elevation;
mod host;
mod input;
mod password;
mod pipeline;
mod portable;
mod rate;
mod session;
mod window;

use std::net::SocketAddr;
use std::path::PathBuf;
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

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Enrol this machine with a server and install the unattended service. [M3]
    Install {
        /// Server address, for example `desk.example.com`.
        #[arg(long)]
        server: String,
        /// Enrollment token issued by an admin.
        #[arg(long)]
        token: String,
    },
    /// Remove the service and this machine's enrollment. [M3]
    Uninstall,
    /// Run in the foreground, connected to the enrolled server. [M2]
    Run,
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
    init_tracing(cli.verbose);
    dpi_aware();

    match cli.command {
        Command::Listen { bind, bitrate_kbps } => {
            let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
            let config = SessionConfig {
                bitrate_kbps,
                password: None,
                host: None,
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
        Command::Install { .. } | Command::Uninstall | Command::Run => {
            anyhow::bail!("not implemented: scheduled for M2/M3, see the roadmap in README.md")
        }
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
            let Ok(_permit) = slot.try_acquire_owned() else {
                tracing::info!(%remote, "turned away: a viewer is already connected");
                conn.close(close::BUSY.into(), b"another viewer is connected");
                return;
            };

            let path = nearhand_transport::rendezvous::path_of(remote);
            tracing::info!(%remote, %path, "viewer connected");
            match session::serve(conn, &config).await {
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

fn init_tracing(verbose: u8) {
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
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();
}
