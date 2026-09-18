//! A bad network on one machine: a UDP forwarder between viewer and agent
//! with a bandwidth cap, a bounded queue, delay and loss — enough of Linux's
//! `netem` to exercise rate control and repair on Windows.
//!
//! ```text
//! nearhand-agent listen --bind 127.0.0.1:4433
//! cargo run --release -p nearhand-transport --example netem -- \
//!     --listen 127.0.0.1:5000 --upstream 127.0.0.1:4433 --down-kbps 3000 --delay-ms 20
//! nearhand-viewer direct 127.0.0.1:5000 --fingerprint …
//! ```
//!
//! Each direction is a link of its own: packets queue for the bandwidth, a
//! packet that would wait longer than `--queue-ms` is dropped (a tail-drop
//! bottleneck), and every packet then takes `--delay-ms` more. `down` is agent
//! to viewer, where the video goes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::time::Instant;

#[derive(Debug, Clone, Copy)]
struct Link {
    /// Zero means unlimited.
    kbps: u64,
    delay: Duration,
    queue: Duration,
    loss_percent: u64,
}

struct Options {
    listen: SocketAddr,
    upstream: SocketAddr,
    down: Link,
    up: Link,
}

fn parse() -> Result<Options, String> {
    let mut listen = None;
    let mut upstream = None;
    let mut down = Link {
        kbps: 0,
        delay: Duration::ZERO,
        queue: Duration::from_millis(100),
        loss_percent: 0,
    };
    let mut up_kbps = 0;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(format!("{flag} needs a value"));
        let number = |v: String| v.parse::<u64>().map_err(|e| format!("{flag}: {e}"));
        match flag.as_str() {
            "--listen" => listen = Some(value()?.parse().map_err(|e| format!("--listen: {e}"))?),
            "--upstream" => {
                upstream = Some(value()?.parse().map_err(|e| format!("--upstream: {e}"))?);
            }
            "--down-kbps" => down.kbps = number(value()?)?,
            "--up-kbps" => up_kbps = number(value()?)?,
            "--delay-ms" => down.delay = Duration::from_millis(number(value()?)?),
            "--queue-ms" => down.queue = Duration::from_millis(number(value()?)?),
            "--loss" => down.loss_percent = number(value()?)?.min(100),
            other => return Err(format!("unknown option {other}")),
        }
    }
    Ok(Options {
        listen: listen.ok_or("--listen is required")?,
        upstream: upstream.ok_or("--upstream is required")?,
        down,
        up: Link {
            kbps: up_kbps,
            ..down
        },
    })
}

/// Windows wakes sleeping threads on a 15.6 ms tick by default, which would
/// add up to that much random delay to every packet — jitter this tool is not
/// asked for. Ask for 1 ms for as long as it runs.
#[cfg(windows)]
fn fine_timer() {
    #[link(name = "winmm")]
    unsafe extern "system" {
        fn timeBeginPeriod(period: u32) -> u32;
    }
    // SAFETY: takes a plain integer; the setting ends with the process.
    unsafe { timeBeginPeriod(1) };
}

#[cfg(not(windows))]
fn fine_timer() {}

#[tokio::main]
async fn main() {
    fine_timer();
    let options = match parse() {
        Ok(options) => options,
        Err(e) => {
            eprintln!("netem: {e}");
            eprintln!(
                "usage: netem --listen ADDR --upstream ADDR [--down-kbps N] [--up-kbps N] \
                 [--delay-ms N] [--queue-ms N] [--loss PERCENT]"
            );
            std::process::exit(2);
        }
    };
    if let Err(e) = run(options).await {
        eprintln!("netem: {e}");
        std::process::exit(1);
    }
}

async fn run(options: Options) -> std::io::Result<()> {
    let near = Arc::new(UdpSocket::bind(options.listen).await?);
    let far = Arc::new(UdpSocket::bind(unspecified_like(options.upstream)).await?);
    far.connect(options.upstream).await?;
    println!(
        "netem: {} -> {}  down {:?}  up {:?}",
        options.listen, options.upstream, options.down, options.up
    );

    // The viewer's address, learned from its first packet.
    let viewer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let dropped = Arc::new(AtomicU64::new(0));

    let (up_tx, up_rx) = mpsc::unbounded_channel();
    let (down_tx, down_rx) = mpsc::unbounded_channel();
    tokio::spawn(shape(options.up, up_rx, dropped.clone(), {
        let far = far.clone();
        move |packet: Vec<u8>| {
            let far = far.clone();
            async move {
                let _ = far.send(&packet).await;
            }
        }
    }));
    tokio::spawn(shape(options.down, down_rx, dropped.clone(), {
        let near = near.clone();
        let viewer = viewer.clone();
        move |packet: Vec<u8>| {
            let near = near.clone();
            let viewer = viewer.clone();
            async move {
                if let Some(to) = *viewer.lock().await {
                    let _ = near.send_to(&packet, to).await;
                }
            }
        }
    }));

    // Agent to viewer.
    tokio::spawn({
        let far = far.clone();
        async move {
            let mut buf = vec![0u8; 65_536];
            while let Ok(n) = far.recv(&mut buf).await {
                let _ = down_tx.send((Instant::now(), buf[..n].to_vec()));
            }
        }
    });

    // Report once a second.
    tokio::spawn({
        let dropped = dropped.clone();
        async move {
            let mut last = 0;
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let now = dropped.load(Ordering::Relaxed);
                if now != last {
                    println!("netem: {} packets dropped in the last second", now - last);
                }
                last = now;
            }
        }
    });

    // Viewer to agent.
    let mut buf = vec![0u8; 65_536];
    loop {
        let (n, from) = near.recv_from(&mut buf).await?;
        *viewer.lock().await = Some(from);
        let _ = up_tx.send((Instant::now(), buf[..n].to_vec()));
    }
}

/// Pass packets through one link, in order: wait for the bandwidth, drop what
/// would queue too long or what the dice say, then add the delay.
async fn shape<F, Fut>(
    link: Link,
    mut packets: mpsc::UnboundedReceiver<(Instant, Vec<u8>)>,
    dropped: Arc<AtomicU64>,
    deliver: F,
) where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut free_at = Instant::now();
    let mut dice = Dice::new();
    while let Some((arrived, packet)) = packets.recv().await {
        let bits = packet.len() as u64 * 8;
        let depart = match (bits * 1000).checked_div(link.kbps) {
            None => arrived,
            Some(transmit_us) => {
                let start = free_at.max(arrived);
                let depart = start + Duration::from_micros(transmit_us);
                if depart - arrived > link.queue {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                free_at = depart;
                depart
            }
        };
        if dice.roll() < link.loss_percent {
            dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        tokio::time::sleep_until(depart + link.delay).await;
        deliver(packet).await;
    }
}

/// xorshift: loss for a test tool does not need a real RNG.
struct Dice(u64);

impl Dice {
    fn new() -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15);
        Self(seed | 1)
    }

    fn roll(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % 100
    }
}

fn unspecified_like(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    }
}
