//! Nearhand server — accounts, devices, permissions, signaling, relay, console.
//!
//! One static binary. Ports 443/UDP (QUIC: introductions and the relay) and
//! 443/TCP (the REST API, and the console to come). Its state is a data
//! folder: the server key, the SQLite database, the HTTPS certificate. See
//! `docs/self-hosting.md`.

mod accounts;
mod api;
mod audit;
mod config;
mod console;
mod db;
mod devices;
mod doctor;
mod grants;
mod https;
#[cfg(test)]
mod netsim;
mod releases;
mod rendezvous;
#[cfg(test)]
mod testkit;
mod totp;
mod webtransport;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nearhand_transport::{Identity, rendezvous_server_config_with_web};

use crate::accounts::Accounts;
use crate::config::Config;
use crate::devices::Devices;
use crate::grants::Grants;

#[derive(Parser, Debug)]
#[command(name = "nearhand-server", version, about, long_about = None)]
struct Cli {
    /// Verbosity: -v for debug, -vv for trace.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Configuration file; environment variables (`NEARHAND_<SECTION>_<KEY>`)
    /// override it. A missing file means the defaults.
    #[arg(long, default_value = "nearhand.toml", global = true)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the server: introductions and relay over QUIC, the REST API over
    /// HTTPS.
    Serve {
        /// Address and UDP port for QUIC, instead of `quic.bind`.
        #[arg(long)]
        bind: Option<SocketAddr>,
        /// Address and TCP port for the API, instead of `http.bind`.
        #[arg(long)]
        http_bind: Option<SocketAddr>,
        /// The server's private key, instead of `server.key` in the data
        /// folder. Agents and viewers pin the certificate made from it: back
        /// it up, because losing it means reconfiguring every one of them.
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Run only the relay, for a standalone relay host. [M5+]
    Relay,
    /// Create or update the database schema, and stop.
    Migrate,
    /// Look at this server without changing it: its key's fingerprint, the
    /// data folder, the database, the certificate and the two ports.
    Doctor,
    /// Print a new one-time link for creating the first administrator.
    AdminLink,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let mut config = Config::load(&cli.config)?;
    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;

    match cli.command {
        Command::Serve {
            bind,
            http_bind,
            key,
        } => {
            if let Some(bind) = bind {
                config.quic.bind = bind;
            }
            if let Some(bind) = http_bind {
                config.http.bind = bind;
            }
            let key = key.unwrap_or_else(|| config.key_path());
            runtime.block_on(serve(config, key))
        }
        Command::Migrate => runtime.block_on(async {
            prepare_data_dir(&config)?;
            db::open(&config.database_path()).await?;
            println!("database up to date: {}", config.database_path().display());
            Ok(())
        }),
        Command::Doctor => runtime.block_on(doctor::run(config, &cli.config)),
        Command::AdminLink => runtime.block_on(async {
            prepare_data_dir(&config)?;
            let accounts = Accounts::new(db::open(&config.database_path()).await?);
            if accounts.has_users().await? {
                println!("There are users already; administrators create more from the API.");
                return Ok(());
            }
            print_setup(&config, &accounts.new_setup_token().await?);
            Ok(())
        }),
        Command::Relay => {
            anyhow::bail!("not implemented: the relay runs inside `serve` for now")
        }
    }
}

async fn serve(config: Config, key: PathBuf) -> Result<()> {
    prepare_data_dir(&config)?;
    let identity = Arc::new(
        Identity::load_or_create(&key)
            .with_context(|| format!("loading the server key from {}", key.display()))?,
    );
    // Browsers get a certificate of their own on the same port.
    let web = webtransport::Web::new(&config)?;
    tokio::spawn(web.clone().keep_renewing());
    let endpoint = quinn::Endpoint::server(
        rendezvous_server_config_with_web(&identity, web.certificate.clone())?,
        config.quic.bind,
    )
    .with_context(|| format!("listening on UDP {}", config.quic.bind))?;
    let pool = db::open(&config.database_path()).await?;
    let accounts = Arc::new(Accounts::new(pool.clone()));
    let first_start = !accounts.has_users().await?;
    let setup_token = if first_start {
        Some(accounts.new_setup_token().await?)
    } else {
        None
    };
    let devices = Arc::new(Devices::new(pool.clone()));
    let grants = Arc::new(Grants::new(pool.clone()));
    let audit = Arc::new(audit::Audit::new(pool.clone()));
    let releases = Arc::new(releases::Releases::new(
        pool.clone(),
        config.releases_dir(),
        nearhand_core::release::KEY,
    ));
    let registry = Arc::new(
        rendezvous::Registry::new(devices.clone())
            .with_access(rendezvous::Access {
                accounts: accounts.clone(),
                grants: grants.clone(),
                identity: identity.clone(),
                audit: audit.clone(),
            })
            .with_releases(releases.clone()),
    );
    let state = Arc::new(api::AppState {
        accounts,
        devices,
        grants,
        audit,
        releases,
        identity: identity.clone(),
        web,
        registry: registry.clone(),
        server: api::ServerInfo {
            address: config.public_address(),
            fingerprint: identity.fingerprint().to_string(),
        },
    });
    let tls = https::server_config(&config)?;
    let handle = axum_server::Handle::new();
    let app = api::router(state).into_make_service_with_connect_info::<SocketAddr>();
    let http = {
        let handle = handle.clone();
        let bind = config.http.bind;
        let tls = tls.clone();
        tokio::spawn(async move {
            let served = match tls {
                Some(tls) => {
                    axum_server::bind_rustls(
                        bind,
                        axum_server::tls_rustls::RustlsConfig::from_config(tls),
                    )
                    .handle(handle)
                    .serve(app)
                    .await
                }
                None => axum_server::bind(bind).handle(handle).serve(app).await,
            };
            served.with_context(|| format!("serving the API on TCP {bind}"))
        })
    };

    // Printed rather than logged: agents and viewers need these to pin and
    // find this server.
    println!("nearhand server on {}", endpoint.local_addr()?);
    println!("fingerprint: {}", identity.fingerprint());
    println!(
        "API on {} ({})",
        config.http.bind,
        if tls.is_some() { "https" } else { "http" }
    );
    if let Some(token) = setup_token {
        print_setup(&config, &token);
    }

    tokio::select! {
        () = rendezvous::serve(endpoint.clone(), registry) => {}
        result = http => {
            // The API stopped on its own: say why, and stop the rest too.
            result.context("the API task")??;
        }
        () = stop_requested() => println!("stopping"),
    }
    handle.graceful_shutdown(Some(Duration::from_secs(5)));
    endpoint.close(0u32.into(), b"server stopping");
    endpoint.wait_idle().await;
    pool.close().await;
    Ok(())
}

/// Until Ctrl+C, or SIGTERM: how `docker stop` and systemd ask a service
/// to stop. A container's first process that does not listen for it is not
/// stopped by it at all, only killed a while later.
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
                return;
            }
            Err(e) => tracing::warn!(error = %e, "cannot listen for SIGTERM; Ctrl+C only"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn prepare_data_dir(config: &Config) -> Result<()> {
    std::fs::create_dir_all(&config.data.dir)
        .with_context(|| format!("creating {}", config.data.dir.display()))
}

/// How to make the first administrator: a link to the console, or one API
/// call. The token is in the link's fragment, which browsers do not send to
/// the server, so it stays out of any proxy's logs.
fn print_setup(config: &Config, token: &str) {
    let url = config.public_url();
    println!();
    println!("No users yet. Within 24 hours, create the first administrator at:");
    println!();
    println!("  {url}/#setup={token}");
    println!();
    println!("or with the API:");
    println!();
    println!("  curl -k {url}/api/v1/setup -H 'content-type: application/json' \\");
    println!(
        "    -d '{{\"token\": \"{token}\", \"name\": \"admin\", \"password\": \"<at least {} characters>\"}}'",
        accounts::MIN_PASSWORD
    );
    println!();
    println!("(The certificate is self-signed unless configured: the browser warns,");
    println!("and curl needs -k. `nearhand-server admin-link` makes a new link.)");
    println!();
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    // Colours only for a person at a terminal, not in `docker logs` or a
    // journal.
    use std::io::IsTerminal as _;
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(std::io::stdout().is_terminal())
        .init();
}
