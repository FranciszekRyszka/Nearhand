//! `nearhand-agent doctor`: why this machine cannot be reached.
//!
//! Almost everything that goes wrong with an installed agent goes wrong in
//! one of a few places — the configuration is missing, the server's name
//! does not resolve, UDP does not get out, the server's key is not the one
//! pinned, the service is not running, or the agent is running and saying
//! so in its log. This walks that list and prints what it finds, so that a
//! person at the machine, or on the phone with one, has something better
//! to go on than "it does not connect".
//!
//! It only looks. It connects to the server and says goodbye without
//! registering, so it cannot disturb the agent that is already registered;
//! it changes nothing on disk.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use nearhand_transport::{Fingerprint, Identity, connect_server, rendezvous_endpoint};

use crate::machine;

/// How long to wait for the server before calling it unreachable.
const REACH_TIMEOUT: Duration = Duration::from_secs(10);
/// How many of a log's last lines to show.
const LOG_LINES: usize = 12;

/// What one check found.
enum Finding {
    /// Nothing to do about this one.
    Good(String),
    /// Worth knowing, not in the way.
    Note(String),
    /// This is what to fix, and how.
    Bad { what: String, fix: String },
}

impl Finding {
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

pub fn run(dir: std::path::PathBuf) -> Result<()> {
    println!("Nearhand agent {}", env!("CARGO_PKG_VERSION"));
    println!("files: {}", dir.display());
    println!();

    let config = match machine::Config::load(&dir) {
        Ok(config) => config,
        Err(e) => {
            Finding::Bad {
                what: format!("{e:#}"),
                fix: "Set this machine up first:\n  \
                      nearhand-agent install --server <address> \\\n    \
                      --server-fingerprint <hex> --password <password>"
                    .to_owned(),
            }
            .print("configuration");
            return Ok(());
        }
    };

    let mut checks: Vec<(&str, Finding)> = Vec::new();
    checks.push(("configuration", Finding::Good(way_in(&config))));
    let identity = match Identity::load_or_create(&machine::key_path(&dir)) {
        Ok(identity) => {
            checks.push((
                "device key",
                Finding::Good(format!("this machine's ID is {}", identity.device_id())),
            ));
            Some(identity)
        }
        Err(e) => {
            checks.push((
                "device key",
                Finding::Bad {
                    what: format!("{e:#}"),
                    fix: "Run this as an administrator; the key is readable by \
                          SYSTEM and administrators only."
                        .to_owned(),
                },
            ));
            None
        }
    };
    checks.push(("service", service()));

    let fingerprint = config.server_fingerprint();
    let address = machine::resolve(&config.server.address);
    match (&address, &fingerprint) {
        (Ok(address), Ok(fingerprint)) => {
            checks.push((
                "server name",
                Finding::Good(format!("{} is {address}", config.server.address)),
            ));
            checks.push(("server", reach(*address, *fingerprint, identity.as_ref())));
        }
        (Err(e), _) => checks.push((
            "server name",
            Finding::Bad {
                what: format!("{} does not resolve: {e:#}", config.server.address),
                fix: "Check the name, and this machine's DNS. `nearhand-agent \
                      install` again with the right address if it has moved."
                    .to_owned(),
            },
        )),
        (_, Err(e)) => checks.push((
            "server key",
            Finding::Bad {
                what: format!("{e:#}"),
                fix: "The fingerprint in agent.toml is not 64 hex digits; the \
                      server prints its own when it starts."
                    .to_owned(),
            },
        )),
    }
    checks.push(("updates", updates(&config, &dir)));

    for (name, finding) in &checks {
        finding.print(name);
    }
    println!();
    show_log(&machine::log_dir(&dir).join("agent.log"), "the agent");
    show_log(&machine::log_dir(&dir).join("service.log"), "the service");

    println!();
    if checks.iter().any(|(_, finding)| finding.is_bad()) {
        println!("Something above is in the way; docs/troubleshooting.md has more.");
    } else {
        println!("Nothing here is in the way of a session.");
        println!("If a viewer still cannot get in, check its end: the device ID,");
        println!("the server it asks, and the password or the grant.");
    }
    Ok(())
}

/// What lets a viewer in, and whether anything does.
fn way_in(config: &machine::Config) -> String {
    match (
        config.managed,
        config.access.is_some(),
        config.password_with_grant,
    ) {
        (true, true, true) => "a grant from the server and the access password together".into(),
        (true, true, false) => "grants from the server, or the access password".into(),
        (true, false, _) => "grants from the server only".into(),
        _ => "the access password only".into(),
    }
}

#[cfg(windows)]
fn service() -> Finding {
    match crate::service::state() {
        Some(state) if format!("{state:?}") == "Running" => Finding::Good("running".into()),
        Some(state) => Finding::Bad {
            what: format!("installed, but {state:?}"),
            fix: "Start it as an administrator:\n  sc start Nearhand\n\
                  Its log is beside this folder, under logs\\service.log."
                .to_owned(),
        },
        None => Finding::Bad {
            what: "not installed".into(),
            fix: "The agent runs as a Windows service; install it with\n  \
                  nearhand-agent install …\nor repair the MSI."
                .to_owned(),
        },
    }
}

#[cfg(not(windows))]
fn service() -> Finding {
    Finding::Note("not a Windows machine: there is no service to check".into())
}

/// Reach the server the way the agent does — the same UDP port, the same
/// pinned certificate — and say goodbye without registering.
fn reach(address: SocketAddr, fingerprint: Fingerprint, identity: Option<&Identity>) -> Finding {
    let Some(identity) = identity else {
        return Finding::Note("not tried: this machine's key could not be read".into());
    };
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            return Finding::Bad {
                what: format!("cannot start a runtime to try with: {e}"),
                fix: String::new(),
            };
        }
    };
    runtime.block_on(async {
        let bind: SocketAddr = if address.is_ipv6() {
            ([0u16; 8], 0).into()
        } else {
            ([0, 0, 0, 0], 0).into()
        };
        let endpoint = match rendezvous_endpoint(bind, identity) {
            Ok(endpoint) => endpoint,
            Err(e) => {
                return Finding::Bad {
                    what: format!("cannot open a socket: {e}"),
                    fix: "Something else may hold every UDP port, or a policy \
                          forbids them."
                        .to_owned(),
                };
            }
        };
        let started = std::time::Instant::now();
        let reached = tokio::time::timeout(
            REACH_TIMEOUT,
            connect_server(&endpoint, address, fingerprint, Some(identity)),
        )
        .await;
        let outcome = match reached {
            Ok(Ok(conn)) => {
                let took = started.elapsed();
                conn.close(0u32.into(), b"doctor");
                Finding::Good(format!(
                    "reached {address} and its key is the one pinned ({took:?})"
                ))
            }
            Ok(Err(e)) => {
                let reason = format!("{e}");
                // A pinned certificate that does not match fails in the
                // handshake, which reads nothing like a blocked port.
                let fix = if reason.contains("certificate") || reason.contains("Invalid") {
                    "The server answered, but not with the key this machine \
                     pinned.\nEither the server was rebuilt with a new key — \
                     install again with\nits new fingerprint — or something \
                     answered in its place."
                } else {
                    "The server did not answer. Check that it is running, that \
                     UDP\nreaches it on this port, and that nothing between \
                     drops QUIC."
                };
                Finding::Bad {
                    what: format!("{address}: {reason}"),
                    fix: fix.to_owned(),
                }
            }
            Err(_) => Finding::Bad {
                what: format!("{address} did not answer within {REACH_TIMEOUT:?}"),
                fix: "UDP is probably not getting out. A firewall, or a \
                      network that\nallows only TCP, will do this; the server \
                      needs its UDP port reachable."
                    .to_owned(),
            },
        };
        endpoint.close(0u32.into(), b"doctor");
        outcome
    })
}

/// Whether the agent updates itself, and what it last downloaded.
fn updates(config: &machine::Config, dir: &Path) -> Finding {
    if !config.updates {
        return Finding::Note("off: agent.toml says updates = false".into());
    }
    let packages = std::fs::read_dir(machine::updates_dir(dir))
        .map(|entries| {
            let mut names: Vec<String> = entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.ends_with(".msi"))
                .collect();
            names.sort();
            names
        })
        .unwrap_or_default();
    match packages.last() {
        Some(last) => Finding::Good(format!("on; last package downloaded: {last}")),
        None => Finding::Good("on; nothing downloaded yet".into()),
    }
}

/// The end of a log, which is where the reason usually is.
fn show_log(path: &Path, whose: &str) {
    let current = std::fs::read_to_string(path).ok();
    let previous = std::fs::read_to_string(crate::logfile::Rotating::previous(path)).ok();
    if current.is_none() && previous.is_none() {
        println!("{whose}: no log at {}", path.display());
        return;
    }
    let lines = last_lines(
        previous.as_deref().unwrap_or_default(),
        current.as_deref().unwrap_or_default(),
        LOG_LINES,
    );
    if lines.is_empty() {
        println!("{whose}: {} is empty", path.display());
        return;
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{whose}, last {} lines of {}:",
        lines.len(),
        path.display()
    );
    for line in lines {
        let _ = writeln!(out, "  {line}");
    }
    print!("{out}");
}

/// The last `n` lines of a log, reaching back into the one before it when
/// the current one has only just started.
fn last_lines<'a>(previous: &'a str, current: &'a str, n: usize) -> Vec<&'a str> {
    let mut lines: Vec<&str> = previous.lines().chain(current.lines()).collect();
    lines.drain(..lines.len().saturating_sub(n));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_just_turned_over_is_shown_with_what_came_before() {
        assert_eq!(
            last_lines(
                "a
b
c
", "d
e
", 3
            ),
            ["c", "d", "e"]
        );
        assert_eq!(
            last_lines(
                "", "d
e
", 3
            ),
            ["d", "e"]
        );
        assert_eq!(
            last_lines(
                "a
", "", 3
            ),
            ["a"]
        );
        assert!(last_lines("", "", 3).is_empty());
    }

    fn config(managed: bool, password: bool, both: bool) -> machine::Config {
        machine::Config {
            server: machine::Server {
                address: "desk.example.com".into(),
                fingerprint: "ab".repeat(32),
            },
            bitrate_kbps: 8000,
            access: password.then(|| crate::access::Stored {
                iterations: 600_000,
                salt: "00".repeat(16),
                hash: "11".repeat(32),
            }),
            managed,
            enrollment: None,
            password_with_grant: both,
            updates: true,
        }
    }

    #[test]
    fn the_way_in_is_named_as_the_agent_would_ask_for_it() {
        assert_eq!(
            way_in(&config(true, true, true)),
            way_in(&config(true, true, true))
        );
        assert!(way_in(&config(true, true, true)).contains("together"));
        assert!(way_in(&config(true, true, false)).contains("or the access password"));
        assert!(way_in(&config(true, false, false)).contains("grants from the server only"));
        assert!(way_in(&config(false, true, false)).contains("access password only"));
    }

    #[test]
    fn a_machine_that_updates_says_what_it_last_took() {
        let dir = std::env::temp_dir().join(format!("nearhand-doctor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(machine::updates_dir(&dir)).expect("scratch");
        let mut config = config(true, true, false);
        assert!(matches!(updates(&config, &dir), Finding::Good(what) if what.contains("nothing")));

        std::fs::write(
            machine::updates_dir(&dir).join("nearhand-agent-0.3.0.msi"),
            b"not really an installer",
        )
        .expect("package");
        assert!(
            matches!(updates(&config, &dir), Finding::Good(what) if what.contains("0.3.0.msi"))
        );

        config.updates = false;
        assert!(matches!(updates(&config, &dir), Finding::Note(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_finding_is_the_one_that_stops_a_session() {
        assert!(
            Finding::Bad {
                what: "nothing works".into(),
                fix: "try turning it off and on again".into(),
            }
            .is_bad()
        );
        assert!(!Finding::Good("fine".into()).is_bad());
        assert!(!Finding::Note("hm".into()).is_bad());
    }
}
