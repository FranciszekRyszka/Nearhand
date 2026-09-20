//! An installed agent at work: registered with its server under the
//! machine's key, letting in whoever has the access password. The service
//! starts it in the console session (`service`); an administrator can also
//! run it in the foreground, to watch what it does.
//!
//! No one is asked to allow a session: that is what unattended means. Two
//! ways in: a grant signed by the server the machine was installed with
//! (`grants`), and the access password if one is set, which the server never
//! sees. Whoever is at the machine sees that a session is on, and whose, for
//! as long as it lasts (`indicator`).
//!
//! An enrollment token that installing could not use yet is used here, once
//! the server can be reached (`enroll`).
//!
//! It also updates itself from that server, unless `agent.toml` says not to
//! (`update`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use nearhand_core::proto::close;
use nearhand_transport::{Identity, server_endpoint};
use quinn::Endpoint;
use tokio::sync::watch;

use crate::access::AccessPassword;
use crate::grants::Grants;
use crate::host::{Host, Server};
use crate::machine;
use crate::session::SessionConfig;

/// Looking the server's name up again after failing: from this, doubling,
/// to the max.
const LOOKUP_RETRY_FIRST: Duration = Duration::from_secs(2);
const LOOKUP_RETRY_MAX: Duration = Duration::from_secs(60);

/// Run from the installation in `dir` until stopped: by the service's
/// `stop_event`, or by Ctrl+C.
pub fn run(dir: PathBuf, stop_event: Option<String>) -> Result<()> {
    let config = machine::Config::load(&dir)
        .context("not installed: set this machine up with `nearhand-agent install` first")?;
    let key = machine::key_path(&dir);
    let identity = Identity::load_or_create(&key).context("loading the device key")?;
    let server_fingerprint = config.server_fingerprint()?;
    // Neither a password nor grants would let anyone at all in.
    if config.access.is_none() && !config.managed {
        anyhow::bail!("agent.toml sets no access password and takes no grants: set a password");
    }
    // Asking for both, with only one of them, would let nobody in either.
    if config.password_with_grant && (config.access.is_none() || !config.managed) {
        anyhow::bail!(
            "agent.toml asks for a grant and the access password together,              but this machine has {}",
            if config.access.is_none() {
                "no password"
            } else {
                "no server to take grants from"
            }
        );
    }
    let address = config.server.address.clone();
    tracing::info!(id = %identity.device_id(), server = %address, "unattended agent starting");

    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    // No window, so no one to ask: grants and the access password decide.
    let host = Host::new(false);
    let session_config = Arc::new(SessionConfig {
        bitrate_kbps: config.bitrate_kbps,
        gate: config
            .access
            .map(|access| Arc::new(AccessPassword::new(access)) as Arc<dyn crate::gate::Gate>),
        grants: config
            .managed
            .then(|| Arc::new(Grants::new(server_fingerprint, identity.fingerprint()))),
        host: Some(host.clone()),
        password_with_grant: config.password_with_grant,
    });
    let updates = config
        .updates
        .then(|| Identity::load_or_create(&key).context("loading the device key"));
    let updates = match updates {
        Some(identity) => Some(identity?),
        None => None,
    };
    let pending = match config.enrollment {
        // A second copy of the key, for enrolling alongside.
        Some(pending) => Some((
            pending,
            Identity::load_or_create(&key).context("loading the device key")?,
        )),
        None => None,
    };
    // Made once the server's address is known: the socket's address family
    // follows it.
    let opened: Arc<Mutex<Option<Endpoint>>> = Arc::default();
    {
        let opened = opened.clone();
        let host = host.clone();
        runtime.spawn(async move {
            let server = look_up(&address, &host).await;
            let endpoint =
                match server_endpoint(crate::portable::unspecified_like(server), &identity) {
                    Ok(endpoint) => endpoint,
                    Err(e) => {
                        tracing::error!(error = %e, "cannot open the socket");
                        host.set_server(Server::Unreachable {
                            error: e.to_string(),
                        });
                        return;
                    }
                };
            *opened.lock().unwrap_or_else(|p| p.into_inner()) = Some(endpoint.clone());
            if let Some(identity) = updates {
                let endpoint = endpoint.clone();
                let host = host.clone();
                tokio::spawn(crate::update::keep_updated(crate::update::Updates {
                    endpoint,
                    server,
                    server_fingerprint,
                    identity,
                    dir: machine::updates_dir(&dir),
                    log: machine::log_dir(&dir).join("update.log"),
                    host,
                    key: nearhand_core::release::KEY,
                    installer: None,
                }));
            }
            if let Some((pending, identity)) = pending {
                let endpoint = endpoint.clone();
                tokio::spawn(async move {
                    crate::enroll::when_possible(
                        &dir,
                        endpoint,
                        server,
                        server_fingerprint,
                        &identity,
                        pending,
                    )
                    .await
                });
            }
            crate::portable::serve(
                endpoint,
                server,
                server_fingerprint,
                identity,
                session_config,
                host,
            )
            .await
        });
    }

    let (stop, mut stopping) = watch::channel(false);
    let waker = host.clone();
    runtime.spawn(async move {
        stop_requested(stop_event).await;
        let _ = stop.send(true);
        // The indicator looks at `stopping` when woken.
        waker.poke();
    });

    // The indicator needs the main thread; the rest runs on the runtime's.
    if let Err(e) = crate::indicator::run(host, stopping.clone()) {
        // A machine without working graphics — a VM without a display
        // adapter — still takes sessions; it just cannot show them.
        tracing::error!(error = %format!("{e:#}"), "no session indicator");
    }
    runtime.block_on(async {
        let _ = stopping.wait_for(|stop| *stop).await;
        let endpoint = opened.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(endpoint) = endpoint {
            endpoint.close(close::NORMAL.into(), b"agent stopping");
            let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
        }
    });
    Ok(())
}

/// The server's address, looked up until found: a service may start before
/// the network, or its name server, is up.
async fn look_up(address: &str, host: &Host) -> SocketAddr {
    let mut wait = LOOKUP_RETRY_FIRST;
    loop {
        let name = address.to_owned();
        let found = tokio::task::spawn_blocking(move || machine::resolve(&name))
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("the lookup task: {e}")));
        match found {
            Ok(server) => {
                tracing::info!(%address, %server, "found the server");
                return server;
            }
            Err(e) => {
                let error = format!("{e:#}");
                tracing::warn!(%error, retry_in = ?wait, "cannot find the server");
                host.set_server(Server::Unreachable { error });
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(LOOKUP_RETRY_MAX);
            }
        }
    }
}

/// Until the service asks the agent to stop through `stop_event`, or Ctrl+C.
async fn stop_requested(stop_event: Option<String>) {
    #[cfg(windows)]
    if let Some(name) = stop_event {
        match crate::service::stop_requested(&name) {
            Ok(stopped) => tokio::select! {
                _ = stopped => tracing::info!("stopping, as the service asked"),
                _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
            },
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "the service cannot stop this agent");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        return;
    }
    #[cfg(not(windows))]
    if stop_event.is_some() {
        tracing::warn!("--stop-event is for the Windows service; ignored");
    }
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("stopping");
}
