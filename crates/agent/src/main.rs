//! Nearhand agent — runs on the controlled machine.
//!
//! Captures the screen, encodes, injects input. Holds one idle outbound QUIC
//! connection to its server and never listens on a port; see `docs/security.md`.

use anyhow::Result;
use clap::{Parser, Subcommand};

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
    /// M0 only: listen for a direct viewer connection on the LAN, no server.
    Listen {
        /// UDP port to bind for QUIC.
        #[arg(long, default_value_t = 4433)]
        port: u16,
        /// Monitor to capture.
        #[arg(long, default_value_t = 0)]
        monitor: u8,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Command::Listen { port, monitor } => {
            tracing::info!(
                port,
                monitor,
                "M0 direct listen mode is not implemented yet"
            );
            anyhow::bail!("not implemented: M0, see the roadmap in README.md");
        }
        Command::Install { .. } | Command::Uninstall | Command::Run | Command::Portable => {
            anyhow::bail!("not implemented: scheduled for M2/M3, see the roadmap in README.md")
        }
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
