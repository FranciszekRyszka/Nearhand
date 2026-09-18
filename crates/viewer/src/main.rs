//! Nearhand viewer — the native controlling app and address book.
//!
//! One GPU path: hardware decode straight into a `wgpu` surface, `egui` for the
//! surrounding UI.

mod direct;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nearhand_transport::Fingerprint;

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
    /// M0 only: connect straight to an agent by address, no server.
    ///
    /// Receives and reassembles the video stream. On-screen presentation is
    /// the next M0 step; `--record` writes the stream to a playable file.
    Direct {
        /// Agent address, for example `192.168.1.20:4433`.
        address: SocketAddr,
        /// The fingerprint the agent printed when it started.
        #[arg(long)]
        fingerprint: Fingerprint,
        /// Which of the agent's monitors to watch.
        #[arg(long, default_value_t = 0)]
        monitor: u8,
        /// Frame-rate cap to ask the agent for.
        #[arg(long, default_value_t = 60)]
        fps: u8,
        /// Disconnect after this many seconds; otherwise run until Ctrl+C.
        #[arg(long)]
        seconds: Option<u64>,
        /// Write the received H.264 stream (Annex B) to this file.
        #[arg(long)]
        record: Option<PathBuf>,
        /// Diagnostic: discard this percentage of incoming datagrams, to
        /// exercise loss recovery on a network that does not lose any.
        #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
        simulate_loss: u8,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Some(Command::Direct {
            address,
            fingerprint,
            monitor,
            fps,
            seconds,
            record,
            simulate_loss,
        }) => {
            let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
            runtime.block_on(direct::run(direct::Options {
                address,
                fingerprint,
                monitor,
                fps: fps.max(1),
                seconds,
                record,
                simulate_loss,
            }))
        }
        // No subcommand opens the address book, which needs a server. [M2]
        None => anyhow::bail!("not implemented: scheduled for M2, see the roadmap in README.md"),
    }
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}
