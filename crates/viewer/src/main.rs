//! Nearhand viewer — the native controlling app and address book.
//!
//! One GPU path: hardware decode straight into a `wgpu` surface, `egui` for the
//! surrounding UI.

mod direct;
mod known;
#[cfg(windows)]
mod present;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(windows)]
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nearhand_core::rendezvous::{DeviceId, Listed};
use nearhand_transport::{Fingerprint, rendezvous};

use crate::direct::Shared;

/// How long to wait for the agent's monitor list before giving up.
#[cfg(windows)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser, Debug)]
#[command(
    name = "nearhand-viewer",
    version,
    about,
    long_about = None,
    arg_required_else_help = true
)]
struct Cli {
    /// Verbosity: -v for debug, -vv for trace.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Connect to a device by its ID, or by its name, through a server.
    ///
    /// Opens a window showing the remote screen and sends it keyboard and
    /// mouse, with a latency overlay (Ctrl+Shift+F1 toggles it).
    /// Ctrl+Shift+F2 switches monitors; Ctrl+Shift+F3 types the clipboard
    /// on the host; Ctrl+Alt+End sends Ctrl+Alt+Del.
    Connect {
        /// The device's ID, as its agent shows it: `123 456 7890`. With a
        /// token, its name as `devices` lists it will do too.
        device: String,
        /// The server's address, for example `203.0.113.10:443`.
        #[arg(long)]
        server: SocketAddr,
        /// The fingerprint the server printed when it started.
        #[arg(long)]
        server_fingerprint: Fingerprint,
        /// The password the agent shows. Asked for if the agent wants one
        /// and it is not given here.
        #[arg(long, conflicts_with = "token")]
        password: Option<String>,
        /// Connect as a user of the server, with an API token of theirs
        /// (`nht_…`): the server hands out a grant for the device if the
        /// user has one. `NEARHAND_TOKEN` in the environment works too, and
        /// stays out of the shell's history.
        #[arg(long)]
        token: Option<String>,
        /// Go through the server's relay even where a direct connection
        /// would work: for testing the relay and measuring what it costs.
        #[arg(long)]
        relay_only: bool,
        /// Connect although the device answers with another key than the
        /// one this viewer saw under that ID before, and remember the new
        /// one. Only when you know why it changed.
        #[arg(long)]
        trust_new_key: bool,
        #[command(flatten)]
        watch: Watch,
    },
    /// List the devices you may connect to through a server: those your
    /// user holds a grant for, and whether each is online.
    Devices {
        /// The server's address, for example `203.0.113.10:443`.
        #[arg(long)]
        server: SocketAddr,
        /// The fingerprint the server printed when it started.
        #[arg(long)]
        server_fingerprint: Fingerprint,
        /// An API token of yours (`nht_…`). `NEARHAND_TOKEN` in the
        /// environment works too, and stays out of the shell's history.
        #[arg(long)]
        token: Option<String>,
    },
    /// List the devices this viewer remembers the key of, and where it
    /// keeps them.
    Known,
    /// Forget a device's key, so the next connection takes whatever key it
    /// answers with. For when you know why it changed; `connect
    /// --trust-new-key` does the same while connecting.
    Forget {
        /// The device's ID: `123 456 7890`.
        id: DeviceId,
    },
    /// Connect straight to an agent's `listen` address, no server.
    Direct {
        /// Agent address, for example `192.168.1.20:4433`.
        address: SocketAddr,
        /// The fingerprint the agent printed when it started.
        #[arg(long)]
        fingerprint: Fingerprint,
        #[command(flatten)]
        watch: Watch,
    },
}

/// How to watch, whichever way the agent was reached.
#[derive(clap::Args, Debug)]
struct Watch {
    /// Which of the agent's monitors to watch.
    #[arg(long, default_value_t = 0)]
    monitor: u8,
    /// Frame-rate cap to ask the agent for.
    #[arg(long, default_value_t = 60)]
    fps: u8,
    /// Disconnect after this many seconds; otherwise run until the window
    /// closes or Ctrl+C.
    #[arg(long)]
    seconds: Option<u64>,
    /// Write the received H.264 stream (Annex B) to this file.
    #[arg(long)]
    record: Option<PathBuf>,
    /// Receive without opening a window.
    #[arg(long)]
    headless: bool,
    /// Diagnostic: discard this percentage of incoming datagrams, to
    /// exercise loss recovery on a network that does not lose any.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u8).range(0..=100))]
    simulate_loss: u8,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    match cli.command {
        Command::Connect {
            device,
            server,
            server_fingerprint,
            password,
            token,
            relay_only,
            trust_new_key,
            watch,
        } => {
            let token = token.or_else(|| {
                std::env::var("NEARHAND_TOKEN")
                    .ok()
                    .filter(|t| !t.is_empty() && password.is_none())
            });
            let id = match device.parse::<DeviceId>() {
                Ok(id) => id,
                Err(_) => {
                    let Some(token) = &token else {
                        bail!(
                            "\"{device}\" is not a device ID (ten digits); a name needs --token, \
                             or NEARHAND_TOKEN, to look it up"
                        );
                    };
                    let (devices, more) = list(server, server_fingerprint, token)?;
                    pick(&devices, more, &device)?
                }
            };
            let route = if relay_only {
                rendezvous::Route::RelayOnly
            } else {
                rendezvous::Route::Best
            };
            let target = direct::Target::Server {
                server,
                server_fingerprint,
                id,
                route,
                token,
            };
            watch_target(target, password, watch, trust_new_key)
        }
        Command::Devices {
            server,
            server_fingerprint,
            token,
        } => {
            let Some(token) = token.or_else(|| {
                std::env::var("NEARHAND_TOKEN")
                    .ok()
                    .filter(|t| !t.is_empty())
            }) else {
                bail!("listing needs an API token: --token, or NEARHAND_TOKEN in the environment");
            };
            let (devices, more) = list(server, server_fingerprint, &token)?;
            print!("{}", table(&devices, more));
            Ok(())
        }
        Command::Known => {
            let known = known::Known::open()?;
            let devices: Vec<_> = known.devices().collect();
            if devices.is_empty() {
                println!("No devices remembered yet.");
            }
            for (id, fingerprint) in devices {
                println!("{id}  {fingerprint}");
            }
            if let Some(path) = known.location() {
                println!("(kept in {})", path.display());
            }
            Ok(())
        }
        Command::Forget { id } => {
            let mut known = known::Known::open()?;
            match known.forget(id)? {
                Some(fingerprint) => println!(
                    "Forgot {id}, which had the key {fingerprint}. The next connection \
                     takes the key it answers with, and remembers that."
                ),
                None => println!("{id} was not remembered; there is nothing to forget."),
            }
            Ok(())
        }
        Command::Direct {
            address,
            fingerprint,
            watch,
        } => {
            let target = direct::Target::Direct {
                address,
                fingerprint,
            };
            watch_target(target, None, watch, false)
        }
    }
}

/// Ask `server` which devices the user whose token this is may reach.
fn list(
    server: SocketAddr,
    server_fingerprint: Fingerprint,
    token: &str,
) -> Result<(Vec<Listed>, u64)> {
    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    runtime.block_on(async {
        let endpoint = nearhand_transport::client_endpoint(server)?;
        rendezvous::devices(&endpoint, server, server_fingerprint, token)
            .await
            .with_context(|| format!("asking {server} for your devices"))
    })
}

/// The one device called `name`, ignoring case. Two with that name, or
/// none, is an error that says which IDs to use instead.
fn pick(devices: &[Listed], more: u64, name: &str) -> Result<DeviceId> {
    let wanted = name.trim().to_lowercase();
    let named: Vec<&Listed> = devices
        .iter()
        .filter(|d| d.name.to_lowercase() == wanted)
        .collect();
    match named.as_slice() {
        [one] => Ok(one.id),
        [] => {
            let near: Vec<String> = devices
                .iter()
                .filter(|d| d.name.to_lowercase().contains(&wanted))
                .take(5)
                .map(|d| format!("{} ({})", d.name, d.id))
                .collect();
            let unlisted = if more > 0 {
                format!("; {more} more were not listed, so give its ID")
            } else {
                String::new()
            };
            if near.is_empty() {
                bail!(
                    "no device called \"{name}\" among the {} you may reach{unlisted}",
                    devices.len()
                )
            }
            bail!(
                "no device called \"{name}\"; did you mean {}{unlisted}",
                near.join(", ")
            )
        }
        several => {
            let ids: Vec<String> = several.iter().map(|d| d.id.to_string()).collect();
            bail!(
                "{} devices are called \"{name}\"; give one's ID: {}",
                several.len(),
                ids.join(", ")
            )
        }
    }
}

/// The answer to `devices`, for a person to read: online ones first, in the
/// server's order within that.
fn table(devices: &[Listed], more: u64) -> String {
    use std::fmt::Write;

    if devices.is_empty() && more == 0 {
        return "No devices: your user holds no grants on this server. An administrator \
                gives them in the console, under Access.\n"
            .to_owned();
    }
    let mut ordered: Vec<_> = devices.iter().collect();
    ordered.sort_by_key(|d| !d.online);
    let mut out = format!(
        "{:<14}{:<9}{:<9}NAME
",
        "ID", "ONLINE", "ROLE"
    );
    for d in ordered {
        let online = if d.online { "yes" } else { "no" };
        let _ = writeln!(
            out,
            "{:<14}{online:<9}{:<9}{}",
            d.id.to_string(),
            d.role.as_str(),
            d.name
        );
    }
    if more > 0 {
        let _ = writeln!(out, "… and {more} more the server did not list");
    }
    out
}

fn watch_target(
    target: direct::Target,
    password: Option<String>,
    watch: Watch,
    trust_new_key: bool,
) -> Result<()> {
    let options = direct::Options {
        target,
        password,
        monitor: watch.monitor,
        fps: watch.fps.max(1),
        seconds: watch.seconds,
        record: watch.record,
        simulate_loss: watch.simulate_loss,
        frames: None,
        input: None,
        cursor: None,
        clipboard: false,
        switch: None,
        shared: Arc::new(Shared::default()),
        trust_new_key,
    };
    if watch.headless {
        let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
        runtime.block_on(direct::run(options))
    } else {
        windowed(options)
    }
}

/// Network on a tokio runtime, decode on its own thread, the window on this
/// one — which Windows requires of the thread that created it.
#[cfg(windows)]
fn windowed(mut options: direct::Options) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new().context("starting the runtime")?;
    let shared = options.shared.clone();
    // Created before the network starts, so pointer changes arriving from the
    // first moment have somewhere to go.
    let event_loop = present::event_loop()?;
    let proxy = event_loop.create_proxy();
    options.clipboard = true;
    let (switch_tx, switch_rx) = tokio::sync::mpsc::unbounded_channel();
    options.switch = Some(switch_rx);
    options.cursor = Some(Arc::new(move |change| {
        let _ = proxy.send_event(present::UserEvent::Cursor(change));
    }));
    let (frames_tx, frames_rx) = std::sync::mpsc::channel();
    options.frames = Some(frames_tx);
    let (input_tx, input_rx) = tokio::sync::mpsc::unbounded_channel();
    options.input = Some(input_rx);
    let title = format!("Nearhand — {}", options.target);
    // The window owns the deadline, so the network side runs until told.
    let seconds = options.seconds.take();
    let network = runtime.spawn(direct::run(options));

    // The window needs the video size before anything can be created; the
    // agent sends it in its monitor list, straight after the handshake.
    let started = Instant::now();
    let video_size = loop {
        if let Some(size) = shared.snapshot().monitor_size {
            break size;
        }
        if network.is_finished() {
            return runtime
                .block_on(network)
                .context("network task panicked")?
                .context("could not start the session");
        }
        if started.elapsed() > CONNECT_TIMEOUT {
            bail!("no monitor list from the agent within {CONNECT_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    // Slots big enough for any of the host's monitors, so switching between
    // them never has to rebuild the textures shared with the decoder.
    let monitors = shared.snapshot().monitors;
    let slot_size = monitors.iter().fold(video_size, |(w, h), m| {
        (w.max(u32::from(m.width)), h.max(u32::from(m.height)))
    });

    let windowed = present::run(
        event_loop,
        present::Options {
            title,
            video_size,
            slot_size,
            frames: frames_rx,
            shared: shared.clone(),
            input: input_tx,
            switch: switch_tx,
            runtime: runtime.handle().clone(),
            seconds,
        },
    );

    // Window closed: say goodbye, then let the decode thread drain.
    shared.stop.notify_one();
    let network = runtime.block_on(network).context("network task panicked")?;
    let decode = windowed?;
    if let Some(thread) = decode {
        let _ = thread.join();
    }
    network
}

#[cfg(not(windows))]
fn windowed(_options: direct::Options) -> Result<()> {
    bail!("the viewer window needs Windows for now (macOS arrives in M4); use --headless")
}

fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => tracing::Level::INFO,
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt().with_max_level(level).init();
}

#[cfg(test)]
mod tests {
    use nearhand_core::grant::Role;
    use nearhand_core::rendezvous::{DeviceId, Listed};

    use super::{pick, table};

    fn listed(id: &str, name: &str, online: bool) -> Listed {
        Listed {
            id: id.parse::<DeviceId>().expect("id"),
            name: name.into(),
            online,
            role: Role::Control,
        }
    }

    #[test]
    fn devices_are_listed_online_first_with_what_was_left_out() {
        let out = table(
            &[
                listed("111 111 1111", "ARCHIVE", false),
                listed("222 222 2222", "RECEPTION-PC", true),
            ],
            3,
        );
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("ID"), "{out}");
        assert!(
            lines[1].starts_with("222 222 2222  yes      control  RECEPTION-PC"),
            "{out}"
        );
        assert!(lines[2].starts_with("111 111 1111  no"), "{out}");
        assert!(lines[3].contains("3 more"), "{out}");
    }

    #[test]
    fn a_device_is_picked_by_its_name_whatever_the_case() {
        let devices = [
            listed("111 111 1111", "ARCHIVE", false),
            listed("222 222 2222", "RECEPTION-PC", true),
            listed("333 333 3333", "Reception-Laptop", true),
        ];
        assert_eq!(
            pick(&devices, 0, "reception-pc").expect("found"),
            "222 222 2222".parse::<DeviceId>().expect("id")
        );
        let missed = pick(&devices, 0, "reception").expect_err("no such name");
        let missed = format!("{missed}");
        assert!(missed.contains("RECEPTION-PC (222 222 2222)"), "{missed}");
        assert!(missed.contains("Reception-Laptop"), "{missed}");
        let unknown = format!("{}", pick(&devices, 4, "kitchen").expect_err("none"));
        assert!(unknown.contains("among the 3"), "{unknown}");
        assert!(unknown.contains("4 more"), "{unknown}");
    }

    #[test]
    fn two_devices_with_one_name_are_not_guessed_between() {
        let devices = [
            listed("111 111 1111", "PC", true),
            listed("222 222 2222", "pc", false),
        ];
        let error = format!("{}", pick(&devices, 0, "PC").expect_err("ambiguous"));
        assert!(
            error.contains("111 111 1111") && error.contains("222 222 2222"),
            "{error}"
        );
    }

    #[test]
    fn no_devices_says_why() {
        let said = table(&[], 0);
        assert!(said.contains("no grants"), "{said}");
        assert!(
            !said.contains("  ") && said.lines().count() == 1,
            "one tidy line: {said}"
        );
    }
}
