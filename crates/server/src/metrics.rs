//! What the server has been doing, for Prometheus: `GET /api/v1/metrics`,
//! with an administrator's API token as the bearer token.
//!
//! Counters are since the server started; gauges are now. Nothing here
//! names a device, a user or an address — only how many.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use nearhand_core::rendezvous::Refusal;

/// Counts kept as the registry works.
pub struct Stats {
    started: Instant,
    introduced: AtomicU64,
    refused: Mutex<BTreeMap<&'static str, u64>>,
    tunnels: AtomicU64,
    relayed_bytes: AtomicU64,
    capped: AtomicU64,
    packages: AtomicU64,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            introduced: AtomicU64::new(0),
            refused: Mutex::default(),
            tunnels: AtomicU64::new(0),
            relayed_bytes: AtomicU64::new(0),
            capped: AtomicU64::new(0),
            packages: AtomicU64::new(0),
        }
    }
}

impl Stats {
    pub fn introduced(&self) {
        self.introduced.fetch_add(1, Ordering::Relaxed);
    }

    pub fn refused(&self, refusal: Refusal) {
        let mut refused = self
            .refused
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *refused.entry(reason(refusal)).or_default() += 1;
    }

    /// A viewer's tunnel opened; it is counted as closed when the returned
    /// guard drops.
    pub fn tunnel(&self) -> Tunnel<'_> {
        self.tunnels.fetch_add(1, Ordering::Relaxed);
        Tunnel(self)
    }

    pub fn relayed(&self, bytes: usize) {
        self.relayed_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn capped(&self) {
        self.capped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn package_sent(&self) {
        self.packages.fetch_add(1, Ordering::Relaxed);
    }
}

/// An open tunnel, for as long as it lives.
pub struct Tunnel<'a>(&'a Stats);

impl Drop for Tunnel<'_> {
    fn drop(&mut self) {
        self.0.tunnels.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Everything the page shows, gathered in one place.
pub struct Snapshot {
    pub version: &'static str,
    pub uptime_secs: u64,
    pub agents_online: usize,
    pub devices_enrolled: usize,
    pub introduced: u64,
    pub refused: Vec<(&'static str, u64)>,
    pub tunnels: u64,
    pub relayed_bytes: u64,
    pub capped: u64,
    pub packages_sending: usize,
    pub packages_sent: u64,
}

impl Stats {
    /// The registry's share of a [`Snapshot`]; the caller fills in the rest.
    pub fn snapshot(&self, agents_online: usize, packages_sending: usize) -> Snapshot {
        let refused = self
            .refused
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(reason, count)| (*reason, *count))
            .collect();
        Snapshot {
            version: env!("CARGO_PKG_VERSION"),
            uptime_secs: self.started.elapsed().as_secs(),
            agents_online,
            devices_enrolled: 0,
            introduced: self.introduced.load(Ordering::Relaxed),
            refused,
            tunnels: self.tunnels.load(Ordering::Relaxed),
            relayed_bytes: self.relayed_bytes.load(Ordering::Relaxed),
            capped: self.capped.load(Ordering::Relaxed),
            packages_sending,
            packages_sent: self.packages.load(Ordering::Relaxed),
        }
    }
}

/// The label a refusal is counted under.
fn reason(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Offline => "offline",
        Refusal::NoCertificate => "no_certificate",
        Refusal::IdTaken => "id_taken",
        Refusal::Declined => "declined",
        Refusal::TooManyAttempts => "too_many_attempts",
        Refusal::Protocol => "protocol",
        Refusal::Enrollment => "enrollment",
        Refusal::NotSignedIn => "not_signed_in",
        Refusal::NotAllowed => "not_allowed",
        Refusal::Busy => "busy",
    }
}

/// `snapshot` in Prometheus' text format.
pub fn render(s: &Snapshot) -> String {
    let mut out = String::new();
    let mut metric = |name: &str, kind: &str, help: &str, samples: &[(String, u64)]| {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} {kind}");
        for (labels, value) in samples {
            let _ = writeln!(out, "{name}{labels} {value}");
        }
    };
    let one = |value: u64| [(String::new(), value)];

    metric(
        "nearhand_build_info",
        "gauge",
        "The server's version, as a label.",
        &[(format!("{{version=\"{}\"}}", s.version), 1)],
    );
    metric(
        "nearhand_uptime_seconds",
        "gauge",
        "Seconds since the server started.",
        &one(s.uptime_secs),
    );
    metric(
        "nearhand_agents_online",
        "gauge",
        "Agents registered now, managed or not.",
        &one(s.agents_online as u64),
    );
    metric(
        "nearhand_devices_enrolled",
        "gauge",
        "Devices in the server's list.",
        &one(s.devices_enrolled as u64),
    );
    metric(
        "nearhand_introductions_total",
        "counter",
        "Viewers introduced to an agent that opened its way to them.",
        &one(s.introduced),
    );
    let refused: Vec<(String, u64)> = s
        .refused
        .iter()
        .map(|(reason, count)| (format!("{{reason=\"{reason}\"}}"), *count))
        .collect();
    metric(
        "nearhand_introductions_refused_total",
        "counter",
        "Viewers refused an introduction, by why.",
        &refused,
    );
    metric(
        "nearhand_relay_tunnels_open",
        "gauge",
        "Viewers' tunnels open now. A viewer that connected directly closes its own at once.",
        &one(s.tunnels),
    );
    metric(
        "nearhand_relayed_bytes_total",
        "counter",
        "Bytes relayed, both directions together.",
        &one(s.relayed_bytes),
    );
    metric(
        "nearhand_relay_ceilings_reached_total",
        "counter",
        "Relayed sessions let go at relay.max_gb.",
        &one(s.capped),
    );
    metric(
        "nearhand_update_downloads_active",
        "gauge",
        "Agent packages being sent now.",
        &one(s.packages_sending as u64),
    );
    metric(
        "nearhand_update_downloads_total",
        "counter",
        "Agent packages sent in full.",
        &one(s.packages_sent),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_come_out_in_prometheus_text() {
        let stats = Stats::default();
        stats.introduced();
        stats.introduced();
        stats.refused(Refusal::Offline);
        stats.refused(Refusal::NotAllowed);
        stats.refused(Refusal::Offline);
        stats.relayed(1500);
        let tunnel = stats.tunnel();
        let mut snapshot = stats.snapshot(3, 1);
        snapshot.devices_enrolled = 7;
        let text = render(&snapshot);
        for line in [
            "nearhand_agents_online 3",
            "nearhand_devices_enrolled 7",
            "nearhand_introductions_total 2",
            "nearhand_introductions_refused_total{reason=\"not_allowed\"} 1",
            "nearhand_introductions_refused_total{reason=\"offline\"} 2",
            "nearhand_relay_tunnels_open 1",
            "nearhand_relayed_bytes_total 1500",
            "nearhand_update_downloads_active 1",
            "# TYPE nearhand_relayed_bytes_total counter",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "missing {line:?} in\n{text}"
            );
        }
        assert!(text.contains(&format!(
            "nearhand_build_info{{version=\"{}\"}} 1",
            env!("CARGO_PKG_VERSION")
        )));

        drop(tunnel);
        assert!(
            render(&stats.snapshot(0, 0))
                .lines()
                .any(|l| l == "nearhand_relay_tunnels_open 0")
        );
    }
}
