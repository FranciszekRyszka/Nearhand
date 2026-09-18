//! Adaptive bitrate: how much video the link can take, re-decided every
//! [`INTERVAL`] from what QUIC and the viewer report.
//!
//! Congestion shows first as delay: a bottleneck's queue fills, and the round
//! trip grows past the path's minimum long before packets drop. Loss alone is
//! a poor signal now that lost chunks are repaired — a few percent of random
//! loss (Wi-Fi) costs a repair each, not the stream, and must not starve the
//! picture. So:
//!
//! * **Overuse** — our own send backlog or the network's queue is growing, or
//!   loss is heavy: back off to below what actually left this machine.
//!   The backlog comes first: it is exact and immediate, where the round trip
//!   QUIC reports is smoothed and trails the queue by seconds.
//! * **Hold** — moderate loss or some queueing: stay put.
//! * **Underuse** — a clean link: probe upwards, but only while the encoder
//!   actually uses the budget. A static desktop sends almost nothing, and
//!   raising the target then would prove nothing about the link.
//!
//! The frame rate follows how much of the budget the encoder uses. Desktop
//! frames usually change a small part of the screen and cost little, so a
//! budget the encoder leaves unused buys frame rate. But when it uses all of
//! it and each frame gets fewer bits than a whole screen of sharp text needs,
//! the frame rate drops instead: on a slow link the picture updates less often
//! rather than turning to mush. Nothing here reads a clock; the caller
//! samples.

use std::collections::VecDeque;
use std::time::Duration;

/// How often the rate is re-decided.
pub const INTERVAL: Duration = Duration::from_millis(500);

/// Never below this: enough for a legible, if slow, desktop.
const FLOOR_KBPS: u32 = 300;
/// Fewest frames per second the rate control will go to.
const MIN_FPS: u8 = 5;
/// Bits each pixel gets per frame, at the least, before the frame rate is
/// cut instead. Screen content at this density keeps text readable.
const BITS_PER_PIXEL: f64 = 0.04;
/// The encoder is starved when it uses this much of the budget or more, and
/// has room to spare at this much or less.
const STARVED_USE: f64 = 0.9;
const ROOMY_USE: f64 = 0.6;

/// Queueing beyond this much above the minimum round trip is overuse. The
/// larger of a fixed margin and half the minimum, so a long path's natural
/// jitter does not count.
const QUEUE_MARGIN: Duration = Duration::from_millis(25);
/// Loss (as a share of QUIC packets) above which the link is overused even
/// without queueing, and above which it is not probed further.
const LOSS_OVERUSE: f64 = 0.10;
const LOSS_HOLD: f64 = 0.02;
/// Probe only when the encoder used at least this share of the budget.
const USED_TO_PROBE: f64 = 0.5;
/// Clean intervals needed before probing upwards.
const CALM_TO_PROBE: u32 = 2;
/// Video waiting in QUIC's send buffer beyond this much time at the target
/// rate is overuse.
const BACKLOG_OVERUSE_MS: u64 = 100;
/// Stop taking frames once the backlog holds this much time at the target
/// rate: capture pauses, and the next frame is fresh rather than queued.
const BACKPRESSURE_MS: u64 = 150;
/// But always allow this much, so one keyframe never stalls on its own.
const BACKPRESSURE_MIN_BYTES: usize = 64 * 1024;
/// Samples the round-trip baseline is the lowest of: 10 s. The baseline is
/// the lowest *smoothed* round trip seen lately, not QUIC's lifetime minimum of
/// raw samples: that one is a single lucky packet, and against it ordinary
/// jitter — Wi-Fi's, or a coarse OS timer's — looks like a queue.
const BASELINE_SAMPLES: usize = 20;
/// Intervals to wait after backing off before backing off again: the round
/// trip QUIC reports is smoothed and trails the queue, so it stays high for a
/// while after the rate has already dropped below the bottleneck.
const SETTLE_AFTER_BACKOFF: u32 = 2;
/// Near the rate where the link last overflowed, probe in small steps rather
/// than climbing straight through it again. Forgotten after this many calm
/// intervals (10 s), because links also get better.
const REMEMBER_OVERUSE: u32 = 20;

/// Cumulative counters, as read at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sample {
    /// QUIC's smoothed round trip.
    pub rtt: Duration,
    /// QUIC packets sent and declared lost, all kinds. QUIC's own count is
    /// the loss signal: the viewer's repair requests would count a chunk once
    /// per request, retries and whole frames included.
    pub sent_packets: u64,
    pub lost_packets: u64,
    /// Video bytes sent, first transmissions only.
    pub sent_bytes: u64,
    /// Bytes waiting in QUIC's datagram send buffer: a current value, not a
    /// running count.
    pub backlog_bytes: u64,
}

/// How much may wait in QUIC's send buffer before the sender stops taking
/// frames.
pub fn backlog_limit(target_kbps: u32) -> usize {
    let bytes = u64::from(target_kbps) * BACKPRESSURE_MS / 8;
    (bytes as usize).max(BACKPRESSURE_MIN_BYTES)
}

/// What the encoder should aim for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quality {
    pub bitrate_kbps: u32,
    pub fps: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Overuse,
    Hold,
    Underuse,
}

/// One interval as the controller read it, for the log.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading {
    pub verdict: Verdict,
    /// Share of QUIC packets QUIC declared lost.
    pub loss: f64,
    pub queue: Duration,
    pub backlog_ms: u64,
}

#[derive(Debug)]
pub struct RateController {
    ceiling: Quality,
    pixels: u64,
    target_kbps: u32,
    fps: u8,
    calm: u32,
    /// Intervals left before another back-off is allowed.
    settling: u32,
    /// Recent smoothed round trips; the lowest is the baseline.
    recent_rtt: VecDeque<Duration>,
    /// What left this machine when the link last overflowed.
    last_overuse_kbps: Option<u32>,
    last_reading: Option<Reading>,
    previous: Option<Sample>,
    applied: Quality,
}

impl RateController {
    /// `ceiling` is the most the viewer asked for; the target starts at
    /// `start_kbps` (the previous stream's, after a monitor switch).
    pub fn new(ceiling: Quality, start_kbps: u32, width: u16, height: u16) -> Self {
        let pixels = u64::from(width) * u64::from(height);
        let target_kbps = start_kbps.clamp(FLOOR_KBPS, ceiling.bitrate_kbps.max(FLOOR_KBPS));
        let mut controller = Self {
            ceiling,
            pixels,
            target_kbps,
            fps: ceiling.fps,
            calm: 0,
            settling: 0,
            recent_rtt: VecDeque::with_capacity(BASELINE_SAMPLES),
            last_overuse_kbps: None,
            last_reading: None,
            previous: None,
            applied: ceiling,
        };
        controller.applied = controller.quality();
        controller
    }

    /// The quality to start the encoder with.
    pub fn initial(&self) -> Quality {
        self.applied
    }

    pub fn target_kbps(&self) -> u32 {
        self.target_kbps
    }

    /// How the last interval was read, if there has been one.
    pub fn last_reading(&self) -> Option<Reading> {
        self.last_reading
    }

    /// The round trip with no queue in it, as far as recent samples show.
    pub fn baseline_rtt(&self) -> Duration {
        self.recent_rtt.iter().copied().min().unwrap_or_default()
    }

    /// The viewer changed what it wants at most.
    pub fn set_ceiling(&mut self, ceiling: Quality) -> Option<Quality> {
        self.ceiling = ceiling;
        self.fps = self.fps.min(ceiling.fps);
        self.target_kbps = self
            .target_kbps
            .clamp(FLOOR_KBPS, ceiling.bitrate_kbps.max(FLOOR_KBPS));
        self.apply()
    }

    /// Take a sample `elapsed` after the previous one. Returns a new quality
    /// when it differs enough from the last one to be worth applying.
    pub fn update(&mut self, sample: Sample, elapsed: Duration) -> Option<Quality> {
        if self.recent_rtt.len() == BASELINE_SAMPLES {
            self.recent_rtt.pop_front();
        }
        self.recent_rtt.push_back(sample.rtt);
        // The first sample only sets the starting point.
        let previous = self.previous.replace(sample)?;
        let secs = elapsed.as_secs_f64().max(0.001);
        let sent_kbps =
            sample.sent_bytes.saturating_sub(previous.sent_bytes) as f64 * 8.0 / 1000.0 / secs;
        // What actually left this machine: sent, less what piled up in the
        // backlog, plus what drained from it.
        let left = (sample.sent_bytes - previous.sent_bytes) as i64 + previous.backlog_bytes as i64
            - sample.backlog_bytes as i64;
        let left_kbps = left.max(0) as f64 * 8.0 / 1000.0 / secs;

        // Against the target the encoder had during the interval.
        let used = sent_kbps / f64::from(self.target_kbps.max(1));
        self.adapt_fps(used);

        let settling = self.settling > 0;
        self.settling = self.settling.saturating_sub(1);
        let reading = read(&previous, &sample, self.target_kbps, self.baseline_rtt());
        self.last_reading = Some(reading);
        match reading.verdict {
            // Already backed off; the queue needs time to drain.
            Verdict::Overuse if settling => self.calm = 0,
            Verdict::Overuse => {
                // Below what actually left, which is the best estimate of the
                // bottleneck while it is full.
                let through = (left_kbps as u32).max(FLOOR_KBPS);
                let backed_off = (f64::from(self.target_kbps.min(through)) * 0.85) as u32;
                self.target_kbps = backed_off.max(FLOOR_KBPS);
                self.calm = 0;
                self.settling = SETTLE_AFTER_BACKOFF;
                self.last_overuse_kbps = Some(through);
            }
            Verdict::Hold => self.calm = 0,
            Verdict::Underuse => {
                self.calm += 1;
                if self.calm >= REMEMBER_OVERUSE {
                    self.last_overuse_kbps = None;
                }
                if self.calm >= CALM_TO_PROBE && used >= USED_TO_PROBE {
                    let near_overuse = self
                        .last_overuse_kbps
                        .is_some_and(|kbps| self.target_kbps * 10 >= kbps * 9);
                    let step = if near_overuse { 1.02 } else { 1.08 };
                    let raised = (f64::from(self.target_kbps) * step) as u32 + 20;
                    self.target_kbps = raised.min(self.ceiling.bitrate_kbps.max(FLOOR_KBPS));
                }
            }
        }
        self.apply()
    }

    /// Fewer frames when the encoder is starved and frames are short of bits
    /// for sharp text; more when it leaves budget unused.
    fn adapt_fps(&mut self, used: f64) {
        let frame_bits = f64::from(self.target_kbps) * 1000.0 / f64::from(self.fps.max(1));
        let sharp_bits = self.pixels.max(1) as f64 * BITS_PER_PIXEL;
        if used >= STARVED_USE && frame_bits < sharp_bits {
            self.fps = (u32::from(self.fps) * 4 / 5) as u8;
        } else if used <= ROOMY_USE {
            self.fps = (u32::from(self.fps) * 5 / 4 + 1).min(255) as u8;
        }
        self.fps = self.fps.clamp(MIN_FPS, self.ceiling.fps.max(MIN_FPS));
    }

    /// The quality for the current target, if it moved far enough from what
    /// the encoder has: every change costs the encoder a reconfiguration.
    fn apply(&mut self) -> Option<Quality> {
        let next = self.quality();
        let old = self.applied;
        let moved = next.fps != old.fps
            || next.bitrate_kbps.abs_diff(old.bitrate_kbps) * 20 > old.bitrate_kbps;
        if moved {
            self.applied = next;
            Some(next)
        } else {
            None
        }
    }

    fn quality(&self) -> Quality {
        Quality {
            bitrate_kbps: self.target_kbps,
            fps: self.fps.clamp(MIN_FPS, self.ceiling.fps.max(MIN_FPS)),
        }
    }
}

/// Read one interval's worth of change between two samples, sending at
/// `target_kbps` over a path whose round trip without a queue is `baseline`.
fn read(previous: &Sample, now: &Sample, target_kbps: u32, baseline: Duration) -> Reading {
    let share = |part: u64, whole: u64| {
        if whole == 0 {
            0.0
        } else {
            part as f64 / whole as f64
        }
    };
    let loss = share(
        now.lost_packets.saturating_sub(previous.lost_packets),
        now.sent_packets.saturating_sub(previous.sent_packets),
    );

    let backlog_ms = now.backlog_bytes * 8 / u64::from(target_kbps.max(1));
    let backlog_growing = now.backlog_bytes >= previous.backlog_bytes;
    let queue = now.rtt.saturating_sub(baseline);
    let margin = QUEUE_MARGIN.max(baseline / 2);
    // A queue that is already shrinking is being drained: the rate is below
    // the bottleneck, however long the queue still is.
    let draining = now.rtt < previous.rtt;

    let verdict = if backlog_ms > BACKLOG_OVERUSE_MS {
        if backlog_growing {
            Verdict::Overuse
        } else {
            Verdict::Hold
        }
    } else if (queue > margin && !draining) || loss > LOSS_OVERUSE {
        Verdict::Overuse
    } else if queue > margin / 2 || loss > LOSS_HOLD {
        Verdict::Hold
    } else {
        Verdict::Underuse
    };
    Reading {
        verdict,
        loss,
        queue,
        backlog_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEN_MS: Duration = Duration::from_millis(10);

    fn verdict(previous: &Sample, now: &Sample, target_kbps: u32, baseline: Duration) -> Verdict {
        read(previous, now, target_kbps, baseline).verdict
    }

    const CEILING: Quality = Quality {
        bitrate_kbps: 10_000,
        fps: 60,
    };

    /// Samples one interval apart: `kbps` of video sent, `loss` of it asked
    /// for again, the round trip at `rtt_ms` over a 10 ms minimum.
    struct Link {
        now: Sample,
    }

    impl Link {
        fn new() -> Self {
            Self {
                now: Sample {
                    rtt: Duration::from_millis(10),
                    ..Sample::default()
                },
            }
        }

        fn backlog(&mut self, bytes: u64) -> Sample {
            self.now.backlog_bytes = bytes;
            self.now
        }

        fn step(&mut self, kbps: u32, loss: f64, rtt_ms: u64) -> Sample {
            let bytes = u64::from(kbps) * 1000 / 8 / 2;
            let chunks = (bytes / 1200).max(1);
            self.now.sent_bytes += bytes;
            self.now.sent_packets += chunks;
            self.now.lost_packets += (chunks as f64 * loss) as u64;
            self.now.rtt = Duration::from_millis(rtt_ms);
            self.now
        }
    }

    fn run(
        c: &mut RateController,
        link: &mut Link,
        steps: usize,
        sent: impl Fn(u32) -> u32,
        loss: f64,
        rtt_ms: u64,
    ) {
        for _ in 0..steps {
            let kbps = sent(c.target_kbps());
            c.update(link.step(kbps, loss, rtt_ms), INTERVAL);
        }
    }

    #[test]
    fn verdicts_follow_queueing_and_loss() {
        let mut link = Link::new();
        let a = link.step(5_000, 0.0, 10);
        let clean = link.step(5_000, 0.0, 12);
        assert_eq!(verdict(&a, &clean, 5_000, TEN_MS), Verdict::Underuse);
        let queued = link.step(5_000, 0.0, 50);
        assert_eq!(verdict(&clean, &queued, 5_000, TEN_MS), Verdict::Overuse);
        let some_queue = link.step(5_000, 0.0, 25);
        assert_eq!(verdict(&queued, &some_queue, 5_000, TEN_MS), Verdict::Hold);
        let lossy = link.step(5_000, 0.05, 10);
        assert_eq!(
            verdict(&some_queue, &lossy, 5_000, TEN_MS),
            Verdict::Hold,
            "repairable loss"
        );
        let very_lossy = link.step(5_000, 0.2, 10);
        assert_eq!(
            verdict(&lossy, &very_lossy, 5_000, TEN_MS),
            Verdict::Overuse
        );
    }

    #[test]
    fn jitter_around_a_steady_path_is_not_a_queue() {
        // Smoothed round trips wandering 40–70 ms: the baseline is the lowest
        // smoothed value, not a lucky raw sample below it.
        let mut c = RateController::new(CEILING, 3_000, 1920, 1080);
        let mut link = Link::new();
        for rtt in [
            55, 62, 48, 70, 51, 66, 45, 69, 58, 64, 47, 70, 53, 68, 50, 67,
        ] {
            c.update(link.step(c.target_kbps(), 0.0, rtt), INTERVAL);
        }
        assert!(
            c.target_kbps() >= 3_000,
            "backed off to {}",
            c.target_kbps()
        );
    }

    #[test]
    fn a_long_path_is_not_mistaken_for_a_queue() {
        let mut link = Link::new();
        let a = link.step(5_000, 0.0, 150);
        // 30 ms of jitter on a 150 ms path is within half the minimum.
        let b = link.step(5_000, 0.0, 180);
        assert_eq!(
            verdict(&a, &b, 5_000, Duration::from_millis(150)),
            Verdict::Underuse
        );
    }

    #[test]
    fn a_bottleneck_pulls_the_rate_below_it() {
        let mut c = RateController::new(CEILING, 10_000, 1920, 1080);
        let mut link = Link::new();
        // A 3 Mbit/s link: whatever is attempted, 3 Mbit/s gets through, and
        // the queue grows while the target is above it. It starts empty, as
        // every connection does.
        let bottleneck = 3_000;
        c.update(link.step(0, 0.0, 10), INTERVAL);
        for _ in 0..30 {
            let target = c.target_kbps();
            let rtt = if target > bottleneck { 80 } else { 12 };
            c.update(link.step(target.min(bottleneck), 0.0, rtt), INTERVAL);
        }
        let target = c.target_kbps();
        // It keeps probing in small steps, so it hovers at the bottleneck
        // rather than strictly below it.
        assert!(
            target <= bottleneck * 105 / 100,
            "target {target} above the bottleneck"
        );
        assert!(
            target >= bottleneck * 6 / 10,
            "target {target} far below it"
        );
    }

    #[test]
    fn a_growing_backlog_is_overuse_before_the_round_trip_shows_it() {
        let mut link = Link::new();
        let a = link.step(5_000, 0.0, 10);
        // 200 ms of video at 5 Mbit/s waiting to be sent; the smoothed round
        // trip has not moved yet.
        link.step(5_000, 0.0, 10);
        let b = link.backlog(125_000);
        assert_eq!(
            verdict(&a, &b, 5_000, Duration::from_millis(150)),
            Verdict::Overuse
        );
        // Long but draining: already below the link, so hold.
        link.step(5_000, 0.0, 10);
        let c = link.backlog(100_000);
        assert_eq!(verdict(&b, &c, 5_000, TEN_MS), Verdict::Hold);
    }

    #[test]
    fn backing_off_uses_what_left_this_machine() {
        let mut c = RateController::new(CEILING, 8_000, 1920, 1080);
        let mut link = Link::new();
        c.update(link.step(8_000, 0.0, 10), INTERVAL);
        // 8 Mbit/s handed over, 250 KB of it still waiting: 4 Mbit/s left.
        link.step(8_000, 0.0, 10);
        c.update(link.backlog(250_000), INTERVAL);
        assert_eq!(c.target_kbps(), 3_400, "85% of the 4 Mbit/s that left");
    }

    #[test]
    fn backpressure_scales_with_the_target_but_fits_a_keyframe() {
        assert_eq!(backlog_limit(10_000), 187_500);
        assert_eq!(backlog_limit(1_000), BACKPRESSURE_MIN_BYTES);
    }

    #[test]
    fn a_draining_queue_is_not_backed_off_from_again() {
        let mut c = RateController::new(CEILING, 6_000, 1920, 1080);
        let mut link = Link::new();
        c.update(link.step(6_000, 0.0, 10), INTERVAL);
        // The queue builds: one back-off.
        c.update(link.step(6_000, 0.0, 120), INTERVAL);
        let after_backoff = c.target_kbps();
        assert!(after_backoff < 6_000);
        // Still long, but shrinking every interval, as the smoothed round
        // trip catches up: no more back-offs.
        for rtt in [115, 105, 95, 80, 60, 40] {
            c.update(link.step(after_backoff, 0.0, rtt), INTERVAL);
        }
        assert_eq!(c.target_kbps(), after_backoff);
    }

    #[test]
    fn back_offs_are_spaced_while_the_queue_holds() {
        let mut c = RateController::new(CEILING, 8_000, 1920, 1080);
        let mut link = Link::new();
        c.update(link.step(8_000, 0.0, 10), INTERVAL);
        let mut targets = Vec::new();
        for _ in 0..6 {
            c.update(link.step(c.target_kbps(), 0.0, 120), INTERVAL);
            targets.push(c.target_kbps());
        }
        // Down, held two intervals, down, held two.
        assert!(targets[0] < 8_000);
        assert_eq!(targets[1], targets[0]);
        assert_eq!(targets[2], targets[0]);
        assert!(targets[3] < targets[2]);
    }

    #[test]
    fn probing_slows_near_where_the_link_last_overflowed() {
        let mut c = RateController::new(CEILING, 2_000, 1920, 1080);
        c.last_overuse_kbps = Some(3_000);
        let mut link = Link::new();
        run(&mut c, &mut link, 12, |target| target, 0.0, 10);
        // 8% steps would be well past 3.5 Mbit/s by now.
        let target = c.target_kbps();
        assert!((2_800..3_300).contains(&target), "target {target}");
    }

    #[test]
    fn a_clean_busy_link_climbs_back_to_the_ceiling() {
        let mut c = RateController::new(CEILING, 1_000, 1920, 1080);
        let mut link = Link::new();
        run(&mut c, &mut link, 60, |target| target, 0.0, 10);
        assert_eq!(c.target_kbps(), CEILING.bitrate_kbps);
    }

    #[test]
    fn an_idle_desktop_does_not_probe() {
        let mut c = RateController::new(CEILING, 2_000, 1920, 1080);
        let mut link = Link::new();
        // A static screen: a trickle, whatever the budget.
        run(&mut c, &mut link, 30, |_| 50, 0.0, 10);
        assert_eq!(c.target_kbps(), 2_000);
    }

    #[test]
    fn random_loss_alone_does_not_starve_the_picture() {
        let mut c = RateController::new(CEILING, 8_000, 1920, 1080);
        let mut link = Link::new();
        run(&mut c, &mut link, 30, |target| target, 0.05, 10);
        assert_eq!(c.target_kbps(), 8_000);
    }

    #[test]
    fn busy_content_on_a_thin_budget_trades_frames_for_sharpness() {
        // Full-screen motion at 1440p, 2 Mbit/s at most: the encoder uses it
        // all.
        let ceiling = Quality {
            bitrate_kbps: 2_000,
            fps: 60,
        };
        let mut c = RateController::new(ceiling, 2_000, 2560, 1440);
        let mut link = Link::new();
        run(&mut c, &mut link, 30, |target| target, 0.0, 10);
        let fps = c.quality().fps;
        // 2 Mbit/s over 3.7 Mpx at 0.04 bit/px affords 13 fps; cuts come in
        // steps of a fifth, so it settles a little below.
        assert!((10..=13).contains(&fps), "fps {fps}");
    }

    #[test]
    fn busy_content_with_bits_to_spare_keeps_its_frame_rate() {
        let mut c = RateController::new(CEILING, 10_000, 1920, 1080);
        let mut link = Link::new();
        run(&mut c, &mut link, 30, |target| target, 0.0, 10);
        assert_eq!(c.quality().fps, 60);
    }

    #[test]
    fn light_content_climbs_back_to_full_frame_rate() {
        let mut c = RateController::new(CEILING, 2_000, 2560, 1440);
        c.fps = 8;
        let mut link = Link::new();
        // A small window changing: a fifth of the budget.
        run(&mut c, &mut link, 20, |target| target / 5, 0.0, 10);
        assert_eq!(c.quality().fps, 60);
    }

    #[test]
    fn the_floor_holds() {
        let c = RateController::new(CEILING, 0, 2560, 1440);
        assert_eq!(c.initial().bitrate_kbps, FLOOR_KBPS);
    }

    #[test]
    fn small_moves_are_not_applied() {
        let mut c = RateController::new(CEILING, 5_000, 1920, 1080);
        c.target_kbps = 5_100;
        assert_eq!(c.apply(), None, "2% is not worth a reconfiguration");
        c.target_kbps = 6_000;
        assert!(c.apply().is_some());
    }

    #[test]
    fn the_ceiling_caps_the_target_at_once() {
        let mut c = RateController::new(CEILING, 10_000, 1920, 1080);
        let q = c
            .set_ceiling(Quality {
                bitrate_kbps: 4_000,
                fps: 30,
            })
            .expect("applied");
        assert_eq!(
            q,
            Quality {
                bitrate_kbps: 4_000,
                fps: 30
            }
        );
    }
}
