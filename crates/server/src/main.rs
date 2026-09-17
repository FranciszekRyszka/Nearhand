//! Nearhand server — accounts, devices, permissions, signaling, relay, console.
//!
//! One static binary. Ports 443/TCP (console, API, WebSocket fallback) and
//! 443/UDP (QUIC: control, WebTransport, relay). See `docs/self-hosting.md`.
//!
//! HTTP, database and console dependencies (`axum`, `sqlx`, `askama`) land in
//! M2 and M5 — they are deliberately not in Cargo.toml yet.

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "nearhand-server", version, about, long_about = None)]
struct Cli {
    /// Verbosity: -v for debug, -vv for trace.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Configuration file; environment variables override it.
    #[arg(long, default_value = "nearhand.toml", global = true)]
    config: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the API, console, signaling and relay. [M2]
    Serve,
    /// Run only the relay, for a standalone relay host. [M2]
    Relay,
    /// Apply pending database migrations. [M5]
    Migrate,
    /// Print a one-time admin setup link. [M5]
    AdminLink,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    tracing::info!(config = %cli.config, command = ?cli.command, "nearhand-server");
    anyhow::bail!("not implemented: scheduled for M2/M5, see the roadmap in README.md")
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}
