//! Nearhand viewer — the native controlling app and address book.
//!
//! One GPU path: hardware decode straight into a `wgpu` surface, `egui` for the
//! surrounding UI.

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    Direct {
        /// Agent address, for example `192.168.1.20:4433`.
        address: String,
        /// Show the capture-to-present latency overlay.
        #[arg(long, default_value_t = true)]
        overlay: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Some(Command::Direct { address, overlay }) => {
            tracing::info!(%address, overlay, "M0 direct connect is not implemented yet");
            anyhow::bail!("not implemented: M0, see the roadmap in README.md");
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
