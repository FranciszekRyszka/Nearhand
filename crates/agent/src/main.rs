//! Nearhand agent — runs on the controlled machine.
//!
//! Captures the screen, encodes, injects input. Holds one idle outbound QUIC
//! connection to its server and never listens on a port; see `docs/security.md`.
//!
//! The one exception is `listen`, the M0 test mode: it accepts a viewer
//! directly on the LAN so the capture-to-screen latency can be measured before
//! any server exists. It goes away once M2 brings signaling.

mod input;
mod pipeline;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nearhand_core::proto::close;
use nearhand_transport::{Identity, server_endpoint};
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
    /// Portable quick-support mode: show an ID and one-time password. [M2]
    Portable,
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
            runtime.block_on(listen(bind, SessionConfig { bitrate_kbps }))
        }
        Command::Install { .. } | Command::Uninstall | Command::Run | Command::Portable => {
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

    let config = Arc::new(config);
    // One viewer at a time: two would fight over the display duplication and
    // the hardware encoder.
    let slot = Arc::new(Semaphore::new(1));

    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => match incoming {
                Some(incoming) => incoming,
                None => break,
            },
            _ = tokio::signal::ctrl_c() => {
                println!("stopping");
                break;
            }
        };

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

            tracing::info!(%remote, "viewer connected");
            match session::serve(conn, &config).await {
                Ok(()) => tracing::info!(%remote, "viewer left"),
                Err(e) => tracing::info!(%remote, error = %format!("{e:#}"), "session ended"),
            }
        });
    }

    endpoint.close(close::NORMAL.into(), b"agent stopping");
    endpoint.wait_idle().await;
    Ok(())
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
    tracing_subscriber::fmt().with_max_level(level).init();
}
