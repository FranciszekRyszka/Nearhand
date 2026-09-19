//! Joining a server's managed devices, once, with an enrollment token an
//! administrator made. Installing tries it straight away; if the server
//! cannot be reached then — a rollout to machines still starting up — the
//! token waits in `agent.toml` and the running agent enrolls when it can.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use nearhand_core::rendezvous::{DeviceId, Enrollment, Refusal};
use nearhand_transport::rendezvous::enroll;
use nearhand_transport::{Error, Fingerprint, Identity};
use quinn::Endpoint;

use crate::machine;

/// How long installing waits for the server before leaving it for later.
const NOW_TIMEOUT: Duration = Duration::from_secs(15);
/// Retrying a server that could not be reached: from this, doubling, to max.
const RETRY_FIRST: Duration = Duration::from_secs(10);
const RETRY_MAX: Duration = Duration::from_secs(5 * 60);

pub enum Outcome {
    Enrolled(DeviceId),
    /// The server said no: the token is wrong, expired or used up. Trying
    /// again would not help.
    Refused(Refusal),
    /// The server could not be asked; worth trying again later.
    Later(String),
}

/// Enroll through `endpoint` with the token in `pending`.
pub async fn once(
    endpoint: &Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
    pending: &machine::Enrollment,
) -> Outcome {
    let request = Enrollment {
        token: pending.token.clone(),
        name: pending.name.clone().unwrap_or_else(computer_name),
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    match enroll(endpoint, server, server_fingerprint, identity, request).await {
        Ok(id) => Outcome::Enrolled(id),
        Err(Error::Refused(refusal)) => Outcome::Refused(refusal),
        Err(e) => Outcome::Later(e.to_string()),
    }
}

/// While installing: enroll now, giving up after a few seconds.
pub fn now(
    address: &str,
    server_fingerprint: Fingerprint,
    identity: &Identity,
    pending: &machine::Enrollment,
) -> Result<Outcome> {
    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    runtime.block_on(async {
        let server = match machine::resolve(address) {
            Ok(server) => server,
            Err(e) => return Ok(Outcome::Later(format!("{e:#}"))),
        };
        let endpoint = nearhand_transport::client_endpoint(server)?;
        let outcome = tokio::time::timeout(
            NOW_TIMEOUT,
            once(&endpoint, server, server_fingerprint, identity, pending),
        )
        .await
        .unwrap_or_else(|_| Outcome::Later("the server did not answer in time".into()));
        endpoint.close(0u32.into(), b"done");
        Ok(outcome)
    })
}

/// While running: enroll with the token waiting in `dir`'s configuration,
/// retrying until the server answers, then forget the token.
pub async fn when_possible(
    dir: &Path,
    endpoint: Endpoint,
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    identity: &Identity,
    pending: machine::Enrollment,
) {
    let mut wait = RETRY_FIRST;
    loop {
        match once(&endpoint, server, server_fingerprint, identity, &pending).await {
            Outcome::Enrolled(id) => {
                tracing::info!(%id, "enrolled with the server");
                break;
            }
            Outcome::Refused(refusal) => {
                tracing::error!(%refusal, "the server refused to enroll this computer; reinstall with a new token");
                break;
            }
            Outcome::Later(error) => {
                tracing::warn!(%error, retry_in = ?wait, "could not enroll yet");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(RETRY_MAX);
            }
        }
    }
    if let Err(e) = forget_token(dir) {
        tracing::error!(error = %format!("{e:#}"), "could not remove the used enrollment token");
    }
}

fn forget_token(dir: &Path) -> Result<()> {
    let mut config = machine::Config::load(dir)?;
    config.enrollment = None;
    config.save(dir)
}

/// This computer's name, to list it under.
pub fn computer_name() -> String {
    let from_env = std::env::var(if cfg!(windows) {
        "COMPUTERNAME"
    } else {
        "HOSTNAME"
    })
    .ok()
    .filter(|name| !name.trim().is_empty());
    from_env
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
        })
        .unwrap_or_else(|| "unnamed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_computer_has_a_name() {
        let name = computer_name();
        assert!(!name.is_empty());
        assert!(!name.contains('\n'));
    }
}
