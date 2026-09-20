//! The server's configuration: one TOML file, every value of which an
//! environment variable can override (`NEARHAND_<SECTION>_<KEY>`), and
//! defaults that serve a first try without either.
//!
//! ```toml
//! [data]
//! dir = "/var/lib/nearhand"      # server.key, nearhand.db, the HTTPS certificate
//!
//! [quic]
//! bind = "0.0.0.0:443"           # UDP: agents, viewers, relay
//! public_address = "desk.example.com:443"   # how agents reach it
//!
//! [audit]
//! keep_days = 365                # 0 keeps the audit log for ever
//!
//! [relay]
//! max_gb = 100                   # per relayed session; 0 lifts the ceiling
//!
//! [http]
//! bind = "0.0.0.0:443"           # TCP: REST API and console
//! tls = "self-signed"            # or "none" behind a reverse proxy,
//!                                # or "files" with cert and key below
//! cert = "/etc/nearhand/fullchain.pem"
//! key = "/etc/nearhand/privkey.pem"
//! public_url = "https://desk.example.com"   # how people reach the console
//! ```

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub data: Data,
    pub quic: Quic,
    pub http: Http,
    pub audit: Audit,
    pub relay: Relay,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Data {
    pub dir: PathBuf,
}

/// What the relay will carry for one session.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Relay {
    /// Gigabytes one relayed session may carry, both directions counted
    /// together, before the server stops carrying it. 0 lifts the ceiling.
    ///
    /// A session at the agent's default 10 Mbps takes a day to reach the
    /// default, so no honest one meets it; it is there so that a server
    /// open to accounts cannot be turned into a tunnel without limit.
    pub max_gb: u64,
}

impl Default for Relay {
    fn default() -> Self {
        Self { max_gb: 100 }
    }
}

impl Relay {
    /// The ceiling in bytes; 0 means none.
    pub fn ceiling(&self) -> u64 {
        self.max_gb.saturating_mul(1024 * 1024 * 1024)
    }
}

/// The audit log's one setting: how long to keep it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Audit {
    /// Days to keep entries for. 0 keeps them for ever — which is a
    /// choice, on a machine whose disk nobody watches.
    pub keep_days: u32,
}

impl Default for Audit {
    fn default() -> Self {
        Self { keep_days: 365 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Quic {
    pub bind: SocketAddr,
    /// How agents and viewers reach this server, `host:port`, for the
    /// install commands it hands out. By default the host of
    /// `http.public_url` and the port of `bind`.
    pub public_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Http {
    pub bind: SocketAddr,
    pub tls: Tls,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub public_url: Option<String>,
}

/// Where the HTTPS certificate comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tls {
    /// Made on first start and kept in the data folder: browsers warn about
    /// it, so it is for trying the server out, or for API clients that pin it.
    SelfSigned,
    /// `cert` and `key`, PEM: a real certificate, from Let's Encrypt or
    /// elsewhere.
    Files,
    /// Plain HTTP, for a reverse proxy in front that does TLS. Bind to
    /// localhost then: passwords cross this connection.
    None,
}

impl Default for Data {
    fn default() -> Self {
        Self { dir: ".".into() }
    }
}

impl Default for Quic {
    fn default() -> Self {
        Self {
            bind: ([0, 0, 0, 0], 443).into(),
            public_address: None,
        }
    }
}

impl Default for Http {
    fn default() -> Self {
        Self {
            bind: ([0, 0, 0, 0], 443).into(),
            tls: Tls::SelfSigned,
            cert: None,
            key: None,
            public_url: None,
        }
    }
}

impl Config {
    /// Read `path` if it exists — no file means all defaults — then apply
    /// the environment.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Self::parse(&text, std::env::vars())
            .with_context(|| format!("in {} or the environment", path.display()))
    }

    fn parse(text: &str, environment: impl Iterator<Item = (String, String)>) -> Result<Self> {
        let mut table: toml::Table = toml::from_str(text).context("not valid TOML")?;
        for (name, value) in environment {
            let Some(rest) = name.strip_prefix("NEARHAND_") else {
                continue;
            };
            let Some((section, key)) = rest
                .to_ascii_lowercase()
                .split_once('_')
                .map(|(s, k)| (s.to_owned(), k.to_owned()))
            else {
                continue;
            };
            if !matches!(
                section.as_str(),
                "data" | "quic" | "http" | "audit" | "relay"
            ) {
                continue;
            }
            let entry = table
                .entry(section.clone())
                .or_insert_with(|| toml::Value::Table(toml::Table::new()));
            let Some(section_table) = entry.as_table_mut() else {
                bail!("[{section}] is not a section");
            };
            // The environment has only strings; TOML has types. A
            // setting that is a number in the file has to be one here too,
            // or it would not parse.
            let value = match (value.parse::<i64>(), value.parse::<bool>()) {
                (Ok(number), _) => toml::Value::Integer(number),
                (_, Ok(yes_no)) => toml::Value::Boolean(yes_no),
                _ => toml::Value::String(value),
            };
            section_table.insert(key, value);
        }
        let config: Self = toml::Value::Table(table)
            .try_into()
            .context("unexpected setting")?;
        config.check()?;
        Ok(config)
    }

    fn check(&self) -> Result<()> {
        if self.http.tls == Tls::Files && (self.http.cert.is_none() || self.http.key.is_none()) {
            bail!("http.tls = \"files\" needs http.cert and http.key");
        }
        if self.http.tls == Tls::None && !self.http.bind.ip().is_loopback() {
            tracing::warn!(
                bind = %self.http.bind,
                "http.tls = \"none\" on an address other than localhost: \
                 passwords would cross the network in the clear"
            );
        }
        Ok(())
    }

    pub fn key_path(&self) -> PathBuf {
        self.data.dir.join("server.key")
    }

    pub fn database_path(&self) -> PathBuf {
        self.data.dir.join("nearhand.db")
    }

    /// Where agent release packages are kept.
    pub fn releases_dir(&self) -> PathBuf {
        self.data.dir.join("releases")
    }

    /// How agents reach the QUIC side, for the install commands the server
    /// hands out.
    pub fn public_address(&self) -> String {
        if let Some(address) = &self.quic.public_address {
            return address.clone();
        }
        let host = crate::https::host_of(&self.public_url()).unwrap_or_else(|| "localhost".into());
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host
        };
        format!("{host}:{}", self.quic.bind.port())
    }

    /// How people reach the console, for links the server prints.
    pub fn public_url(&self) -> String {
        match &self.http.public_url {
            Some(url) => url.trim_end_matches('/').to_owned(),
            None => {
                let scheme = if self.http.tls == Tls::None {
                    "http"
                } else {
                    "https"
                };
                let port = self.http.bind.port();
                let default =
                    (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
                if default {
                    format!("{scheme}://localhost")
                } else {
                    format!("{scheme}://localhost:{port}")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> impl Iterator<Item = (String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn nothing_given_means_defaults() {
        let config = Config::parse("", env(&[])).expect("parse");
        assert_eq!(config.data.dir, PathBuf::from("."));
        assert_eq!(config.audit.keep_days, 365);
        assert_eq!(config.relay.ceiling(), 100 * 1024 * 1024 * 1024);
        assert_eq!(config.quic.bind.port(), 443);
        assert_eq!(config.http.tls, Tls::SelfSigned);
        assert_eq!(config.public_url(), "https://localhost");
        assert_eq!(config.public_address(), "localhost:443");
    }

    /// How long the audit log is kept is a setting like any other, and 0
    /// means for ever.
    #[test]
    fn the_audit_log_is_kept_for_a_year_unless_told_otherwise() {
        let set = Config::parse(
            "[audit]
keep_days = 30
",
            env(&[]),
        )
        .expect("parse");
        assert_eq!(set.audit.keep_days, 30);
        let forever = Config::parse("", env(&[("NEARHAND_AUDIT_KEEP_DAYS", "0")])).expect("parse");
        assert_eq!(forever.audit.keep_days, 0);
    }

    #[test]
    fn the_file_sets_and_the_environment_overrides() {
        let text = r#"
            [data]
            dir = "/var/lib/nearhand"
            [http]
            bind = "127.0.0.1:8080"
            tls = "none"
            public_url = "https://desk.example.com/"
        "#;
        let config = Config::parse(
            text,
            env(&[
                ("NEARHAND_DATA_DIR", "/srv/nearhand"),
                ("NEARHAND_QUIC_BIND", "0.0.0.0:4433"),
                ("UNRELATED", "x"),
                ("NEARHAND_OTHER_THING", "ignored"),
            ]),
        )
        .expect("parse");
        assert_eq!(config.data.dir, PathBuf::from("/srv/nearhand"));
        assert_eq!(config.quic.bind.port(), 4433);
        assert_eq!(config.http.tls, Tls::None);
        assert_eq!(config.public_url(), "https://desk.example.com");
        assert_eq!(config.public_address(), "desk.example.com:4433");
        let set = Config::parse(
            "",
            env(&[("NEARHAND_QUIC_PUBLIC_ADDRESS", "203.0.113.5:443")]),
        )
        .expect("parse");
        assert_eq!(set.public_address(), "203.0.113.5:443");
    }

    #[test]
    fn mistakes_are_reported_not_ignored() {
        assert!(Config::parse("[http]\nbnid = \"x\"", env(&[])).is_err());
        assert!(Config::parse("[http]\ntls = \"files\"", env(&[])).is_err());
        assert!(Config::parse("", env(&[("NEARHAND_HTTP_BIND", "nonsense")])).is_err());
    }
}
