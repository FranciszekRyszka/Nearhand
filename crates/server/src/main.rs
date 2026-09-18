//! Nearhand server — accounts, devices, permissions, signaling, relay, console.
//!
//! One static binary. Ports 443/TCP (console, API, WebSocket fallback) and
//! 443/UDP (QUIC: control, WebTransport, relay). See `docs/self-hosting.md`.
//!
//! HTTP, database and console dependencies (`axum`, `sqlx`, `askama`) land in
//! M5 — they are deliberately not in Cargo.toml yet. So far the server does
//! introductions (`rendezvous`), over QUIC only.

mod rendezvous;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nearhand_transport::{Identity, rendezvous_endpoint};

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
    /// Introduce viewers to agents by device ID. [M2: relay to come; API
    /// and console in M5]
    Serve {
        /// Address and UDP port for QUIC.
        #[arg(long, default_value = "0.0.0.0:443")]
        bind: SocketAddr,
        /// The server's private key, created on first start. Agents and
        /// viewers pin the certificate made from it: back it up, because
        /// losing it means reconfiguring every one of them.
        #[arg(long, default_value = "server.key")]
        key: PathBuf,
    },
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

    match cli.command {
        Command::Serve { bind, key } => {
            let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
            runtime.block_on(serve(bind, key))
        }
        Command::Relay | Command::Migrate | Command::AdminLink => {
            anyhow::bail!("not implemented: scheduled for M2/M5, see the roadmap in README.md")
        }
    }
}

async fn serve(bind: SocketAddr, key: PathBuf) -> Result<()> {
    let identity = Identity::load_or_create(&key)
        .with_context(|| format!("loading the server key from {}", key.display()))?;
    let endpoint =
        rendezvous_endpoint(bind, &identity).with_context(|| format!("listening on {bind}"))?;
    // Printed rather than logged: agents and viewers need it to pin this
    // server.
    println!("nearhand server on {}", endpoint.local_addr()?);
    println!("fingerprint: {}", identity.fingerprint());

    let registry = Arc::new(rendezvous::Registry::default());
    tokio::select! {
        () = rendezvous::serve(endpoint.clone(), registry) => {}
        _ = tokio::signal::ctrl_c() => println!("stopping"),
    }
    endpoint.close(0u32.into(), b"server stopping");
    endpoint.wait_idle().await;
    Ok(())
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}
