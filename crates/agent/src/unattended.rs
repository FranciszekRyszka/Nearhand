//! An installed agent at work: registered with its server under the
//! machine's key, letting in whoever has the access password. The service
//! starts it in the console session (`service`); an administrator can also
//! run it in the foreground, to watch what it does.
//!
//! No one is asked to allow a session: that is what unattended means. The
//! access password is the only way in, and the server never sees it.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use nearhand_core::proto::close;
use nearhand_transport::{Identity, server_endpoint};

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
        host,
    ));

    runtime.block_on(async {
        match stop_event {
            #[cfg(windows)]
            Some(name) => {
                let stopped = crate::service::stop_requested(&name)?;
                tokio::select! {
                    _ = stopped => tracing::info!("stopping, as the service asked"),
                    _ = tokio::signal::ctrl_c() => tracing::info!("stopping"),
                }
            }
            #[cfg(not(windows))]
            Some(_) => anyhow::bail!("--stop-event is for the Windows service"),
            None => {
                let _ = tokio::signal::ctrl_c().await;
                tracing::info!("stopping");
            }
        }
        endpoint.close(close::NORMAL.into(), b"agent stopping");
        let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.wait_idle()).await;
        Ok(())
    })
}
