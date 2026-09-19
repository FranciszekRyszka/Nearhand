//! An installed agent at work: registered with its server under the
//! machine's key, letting in whoever has the access password. The service
//! starts it in the console session (`service`); an administrator can also
//! run it in the foreground, to watch what it does.
//!
//! No one is asked to allow a session: that is what unattended means. The
//! access password is the only way in, and the server never sees it. But
//! whoever is at the machine sees that a session is on, for as long as it
//! lasts (`indicator`).

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nearhand_core::proto::close;
use nearhand_transport::{Identity, server_endpoint};
use tokio::sync::watch;

use crate::access::AccessPassword;
use crate::host::Host;
use crate::machine;
use crate::session::SessionConfig;

/// Run from the installation in `dir` until stopped: by the service's
/// `stop_event`, or by Ctrl+C.
pub fn run(dir: std::path::PathBuf, stop_event: Option<String>) -> Result<()> {
    let config = machine::Config::load(&dir)
        .context("not installed: set this machine up with `nearhand-agent install` first")?;
    let identity =
        Identity::load_or_create(&machine::key_path(&dir)).context("loading the device key")?;
    let server = config.server.address;
    let server_fingerprint = config.server_fingerprint()?;
    tracing::info!(id = %identity.device_id(), %server, "unattended agent starting");

    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    let endpoint = {
        let _inside = runtime.enter();
        server_endpoint(crate::portable::unspecified_like(server), &identity)
            .context("opening the socket")?
    };
    // No window, so no one to ask: the access password decides.
    let host = Host::new(false);
    let session_config = Arc::new(SessionConfig {
        bitrate_kbps: config.bitrate_kbps,
        gate: Some(Arc::new(AccessPassword::new(config.access))),
        host: Some(host.clone()),
    });
    runtime.spawn(crate::portable::serve(
        endpoint.clone(),
        server,
        server_fingerprint,
        identity,
        session_config,
        host.clone(),
    ));

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
        endpoint.close(close::NORMAL.into(), b"agent stopping");
        let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
    });
    Ok(())
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
