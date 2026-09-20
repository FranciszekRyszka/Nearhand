//! `nearhand-server doctor`: what is in the way, and what this server is.
//!
//! The agent has one of these (`nearhand-agent doctor`); this is the other
//! end. It reads the configuration, the data folder, the key, the database
//! and the certificate, tries the two ports, and says what it found — and
//! it prints the fingerprint agents pin, which otherwise only appears in
//! the log when the server starts.
//!
//! It does not migrate the database, bind the ports for longer than the
//! moment it takes to try, or change anything on disk.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::config::{Config, Tls};

/// What one check found.
pub enum Finding {
    /// Nothing to do about this one.
    Good(String),
    /// Worth knowing, not in the way.
    Note(String),
    /// This is what to fix, and how.
    Bad { what: String, fix: String },
}

impl Finding {
    fn bad(what: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::Bad {
            what: what.into(),
            fix: fix.into(),
        }
    }

    fn print(&self, name: &str) {
        match self {
            Self::Good(what) => println!("  ok   {name}: {what}"),
            Self::Note(what) => println!("  --   {name}: {what}"),
            Self::Bad { what, fix } => {
                println!("  NO   {name}: {what}");
                for line in fix.lines() {
                    println!("       {line}");
                }
            }
        }
    }

    fn is_bad(&self) -> bool {
        matches!(self, Self::Bad { .. })
    }
}

pub async fn run(config: Config, config_path: &Path) -> Result<()> {
    println!("nearhand server {}", env!("CARGO_PKG_VERSION"));
    println!(
        "configuration: {}{}",
        config_path.display(),
        if config_path.exists() {
            ""
        } else {
            " (missing: defaults, and the environment)"
        }
    );
    println!("data:          {}", config.data.dir.display());
    println!();

    let checks = checks(&config).await;
    for (name, finding) in &checks {
        finding.print(name);
    }
    println!();
    if checks.iter().any(|(_, finding)| finding.is_bad()) {
        println!("Something above is in the way; docs/troubleshooting.md has more.");
    } else {
        println!("Nothing here is in the way of agents and viewers.");
    }
    Ok(())
}

/// Every check, in the order a person would want them.
pub async fn checks(config: &Config) -> Vec<(&'static str, Finding)> {
    let mut checks = vec![("data folder", data_folder(&config.data.dir))];
    checks.push(("server key", key(config)));
    checks.push(("database", database(config).await));
    checks.push(("audit log", audit(config)));
    checks.push(("releases", releases(config)));
    checks.push(("certificate", certificate(config)));
    checks.push(("UDP port", udp(config.quic.bind)));
    checks.push(("TCP port", tcp(config.http.bind)));
    checks.push(("public address", public(config)));
    checks
}

/// It must exist and take writes: the key, the database and the releases
/// all live here.
fn data_folder(dir: &Path) -> Finding {
    if !dir.exists() {
        return Finding::Note(format!(
            "{} does not exist yet; the server makes it at first start",
            dir.display()
        ));
    }
    let probe = dir.join(".nearhand-doctor");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Finding::Good("exists and takes writes".into())
        }
        Err(e) => Finding::bad(
            format!("cannot write in {}: {e}", dir.display()),
            "The server writes its key, database and releases here. In \
             Docker this is\nusually a volume that is not mounted, or \
             mounted read-only.",
        ),
    }
}

/// The key behind the certificate every agent and viewer pins.
fn key(config: &Config) -> Finding {
    let path = config.key_path();
    if !path.exists() {
        return Finding::Note(
            "no key yet: the server makes one at first start, and agents pin it".into(),
        );
    }
    match nearhand_transport::Identity::load_or_create(&path) {
        Ok(identity) => Finding::Good(format!(
            "fingerprint {} — what agents and viewers pin",
            identity.fingerprint()
        )),
        Err(e) => Finding::bad(
            format!("{}: {e:#}", path.display()),
            "Without this key the server cannot be the server agents \
             pinned.\nRestore it from a backup; a new one means \
             reconfiguring every agent.",
        ),
    }
}

/// Opened as it is, without migrating: a doctor does not change things.
async fn database(config: &Config) -> Finding {
    let path = config.database_path();
    if !path.exists() {
        return Finding::Note("no database yet; the server makes one at first start".into());
    }
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(false)
        .read_only(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = match SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
    {
        Ok(pool) => pool,
        Err(e) => {
            return Finding::bad(
                format!("{}: {e}", path.display()),
                "A database that cannot be opened is usually one being \
                 written by\nanother server, or one on a filesystem that \
                 does not do locking.",
            );
        }
    };
    let counted = summary(&pool).await;
    pool.close().await;
    match counted {
        Ok(summary) => summary,
        Err(e) => Finding::bad(
            format!("cannot read {}: {e}", path.display()),
            "The schema may be older than this server. `nearhand-server \
             migrate` brings it up to date.",
        ),
    }
}

/// Who and what is in the database.
async fn summary(pool: &SqlitePool) -> Result<Finding, sqlx::Error> {
    // One row, four numbers: a literal query, as sqlx insists and as is
    // right for anything that reaches a database.
    let row = sqlx::query(
        r#"SELECT
             (SELECT count(*) FROM users) AS users,
             (SELECT count(*) FROM devices) AS devices,
             (SELECT count(*) FROM grants) AS grants,
             (SELECT count(*) FROM devices
                WHERE last_seen_at > strftime('%s', 'now') - 604800) AS recent"#,
    )
    .fetch_one(pool)
    .await?;
    let users: i64 = row.try_get("users")?;
    let devices: i64 = row.try_get("devices")?;
    let grants: i64 = row.try_get("grants")?;
    let recent: i64 = row.try_get("recent")?;
    if users == 0 {
        return Ok(Finding::Note(
            "no users yet: `nearhand-server admin-link` prints a link for the first one".into(),
        ));
    }
    Ok(Finding::Good(format!(
        "{users} users, {devices} devices ({recent} seen this week), {grants} grants"
    )))
}

/// How long the record of who did what is kept.
fn audit(config: &Config) -> Finding {
    match config.audit.keep_days {
        0 => Finding::Note(
            "audit.keep_days = 0: entries are kept for ever, and nothing \
             watches the disk"
                .into(),
        ),
        days => Finding::Good(format!(
            "entries older than {days} days are swept daily (audit.keep_days)"
        )),
    }
}

/// What agents would be offered, and what it costs on disk.
fn releases(config: &Config) -> Finding {
    let dir = config.releases_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Finding::Note("no releases held for agents to update from".into());
    };
    let (mut count, mut bytes) = (0u64, 0u64);
    for entry in entries.flatten() {
        if let Ok(meta) = entry.metadata()
            && meta.is_file()
        {
            count += 1;
            bytes += meta.len();
        }
    }
    if count == 0 {
        return Finding::Note("no releases held for agents to update from".into());
    }
    Finding::Good(format!(
        "{count} package{} held, {:.1} MB — the console says which is offered",
        if count == 1 { "" } else { "s" },
        bytes as f64 / (1024.0 * 1024.0)
    ))
}

/// The certificate browsers see, built the same way `serve` builds it.
fn certificate(config: &Config) -> Finding {
    match config.http.tls {
        Tls::None => Finding::Note(
            "http.tls = \"none\": something in front must do TLS, and this \
             must bind to localhost"
                .into(),
        ),
        Tls::SelfSigned => match crate::https::server_config(config) {
            Ok(_) => Finding::Good(
                "self-signed: browsers warn, and curl needs -k. `tls = \"files\"` \
                 takes a real one"
                    .into(),
            ),
            Err(e) => Finding::bad(
                format!("cannot make a self-signed certificate: {e:#}"),
                "The data folder must take writes: the certificate is kept there.",
            ),
        },
        Tls::Files => match crate::https::server_config(config) {
            Ok(_) => Finding::Good(format!(
                "from {} and its key",
                config
                    .http
                    .cert
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "http.cert".into())
            )),
            Err(e) => Finding::bad(
                format!("{e:#}"),
                "http.cert and http.key must both be PEM, and be each \
                 other's.\nAfter a renewal, restart the server so it reads \
                 them again.",
            ),
        },
    }
}

/// Agents, viewers and the relay all arrive on this UDP port.
fn udp(bind: SocketAddr) -> Finding {
    match std::net::UdpSocket::bind(bind) {
        Ok(socket) => {
            drop(socket);
            Finding::Good(format!("{bind} is free to bind"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Finding::Note(format!(
            "{bind} is in use — by this server, if it is running"
        )),
        Err(e) => Finding::bad(
            format!("cannot bind {bind}: {e}"),
            "A port under 1024 needs a capability on Linux:\n  setcap \
             'cap_net_bind_service=+ep' /usr/local/bin/nearhand-server\nor \
             run behind something that forwards UDP.",
        ),
    }
}

/// The REST API and the console.
fn tcp(bind: SocketAddr) -> Finding {
    match std::net::TcpListener::bind(bind) {
        Ok(listener) => {
            drop(listener);
            Finding::Good(format!("{bind} is free to bind"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => Finding::Note(format!(
            "{bind} is in use — by this server, if it is running"
        )),
        Err(e) => Finding::bad(
            format!("cannot bind {bind}: {e}"),
            "A port under 1024 needs a capability on Linux, or a proxy in \
             front.",
        ),
    }
}

/// What the server tells agents to come back to. A name only it can
/// resolve, or a loopback address, means the install commands it hands out
/// do not work anywhere else.
fn public(config: &Config) -> Finding {
    let address = config.public_address();
    let host = address
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .unwrap_or(&address);
    let looks_local = host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback() || ip.is_unspecified())
            .unwrap_or(false);
    if looks_local {
        return Finding::bad(
            format!("agents would be told to reach this server at {address}"),
            "Set quic.public_address (or http.public_url) to the name or \
             address\nagents and viewers use from outside this machine.",
        );
    }
    Finding::Good(format!("agents are told to reach {address}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path) -> Config {
        let mut config = Config::default();
        config.data.dir = dir.to_path_buf();
        config.quic.bind = "127.0.0.1:0".parse().expect("address");
        config.http.bind = "127.0.0.1:0".parse().expect("address");
        config.quic.public_address = Some("desk.example.com:443".into());
        config
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nearhand-server-doctor-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    #[tokio::test]
    async fn a_fresh_folder_is_nothing_to_worry_about() {
        let dir = scratch("fresh");
        let checks = checks(&config(&dir)).await;
        for (name, finding) in &checks {
            assert!(!finding.is_bad(), "{name} was in the way");
        }
        // Nothing has been made: a doctor only looks.
        assert!(!config(&dir).key_path().exists());
        assert!(!config(&dir).database_path().exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_database_is_read_and_counted_without_migrating_it() {
        let dir = scratch("counted");
        let config = config(&dir);
        // A real one, made the way the server makes it.
        let pool = crate::db::open(&config.database_path())
            .await
            .expect("database");
        pool.close().await;

        let finding = database(&config).await;
        assert!(
            matches!(&finding, Finding::Note(what) if what.contains("no users yet")),
            "a fresh database has no users"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_address_only_this_machine_could_use_is_called_out() {
        let dir = scratch("public");
        let mut config = config(&dir);
        for local in ["localhost:443", "127.0.0.1:443", "0.0.0.0:443", "[::1]:443"] {
            config.quic.public_address = Some(local.into());
            assert!(public(&config).is_bad(), "{local}");
        }
        for outside in ["desk.example.com:443", "203.0.113.10:4433"] {
            config.quic.public_address = Some(outside.into());
            assert!(!public(&config).is_bad(), "{outside}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_folder_that_cannot_be_written_is_in_the_way() {
        let dir = scratch("unwritable");
        assert!(!data_folder(&dir).is_bad());
        // A file where the folder should be: the same to everything that
        // writes there.
        let path = dir.join("not-a-folder");
        std::fs::write(&path, b"x").expect("file");
        assert!(data_folder(&path).is_bad());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
