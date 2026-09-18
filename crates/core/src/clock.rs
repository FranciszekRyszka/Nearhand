//! Placing the agent's capture timestamps on the viewer's clock.
//!
//! The two machines' clocks have unrelated epochs, so glass-to-glass latency
//! needs their offset. Each [`Control::Ping`](crate::Control::Ping) /
//! [`Control::Pong`](crate::Control::Pong) exchange yields one estimate, the
//! way NTP does: assume the agent answered at the midpoint of the round trip.
//! The error is at most half the round trip, so the sample with the smallest
//! round trip in a recent window is the one trusted — queueing only ever adds
//! delay, so the fastest exchange is the least distorted.
//!
//! No clock is read here, which keeps it usable from the browser viewer.

use std::collections::VecDeque;

/// How many recent exchanges are considered. At one probe a second this
/// spans half a minute: long enough to catch a quiet moment on the network,
/// short enough to follow the slow drift between two crystals.
const WINDOW: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sample {
    rtt_us: u64,
    /// Agent clock minus viewer clock.
    offset_us: i64,
}

#[derive(Debug, Default)]
pub struct ClockSync {
    samples: VecDeque<Sample>,
}

impl ClockSync {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one exchange: the viewer's clock when the Ping left and when the
    /// Pong arrived, and the agent's clock in the Pong.
    pub fn add(&mut self, sent_us: u64, agent_us: u64, received_us: u64) {
        let Some(rtt_us) = received_us.checked_sub(sent_us) else {
            return; // A clock that ran backwards tells us nothing.
        };
        let midpoint = sent_us + rtt_us / 2;
        let offset_us = agent_us as i128 - midpoint as i128;
        let Ok(offset_us) = i64::try_from(offset_us) else {
            return;
        };
        if self.samples.len() == WINDOW {
            self.samples.pop_front();
        }
        self.samples.push_back(Sample { rtt_us, offset_us });
    }

    fn best(&self) -> Option<Sample> {
        self.samples.iter().copied().min_by_key(|s| s.rtt_us)
    }

    /// Agent clock minus viewer clock, in microseconds.
    pub fn offset_us(&self) -> Option<i64> {
        self.best().map(|s| s.offset_us)
    }

    /// How far off [`offset_us`](Self::offset_us) can be: half the best round
    /// trip.
    pub fn uncertainty_us(&self) -> Option<u64> {
        self.best().map(|s| s.rtt_us / 2)
    }

    /// An agent timestamp expressed on the viewer's clock.
    pub fn to_viewer_us(&self, agent_us: u64) -> Option<u64> {
        let viewer = agent_us as i128 - i128::from(self.offset_us()?);
        u64::try_from(viewer).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_delay_recovers_the_exact_offset() {
        let mut sync = ClockSync::new();
        // Agent is 5 s ahead; 1 ms each way.
        sync.add(1_000_000, 6_001_000, 1_002_000);
        assert_eq!(sync.offset_us(), Some(5_000_000));
        assert_eq!(sync.uncertainty_us(), Some(1_000));
        assert_eq!(sync.to_viewer_us(6_500_000), Some(1_500_000));
    }

    #[test]
    fn asymmetric_delay_stays_within_half_the_round_trip() {
        let mut sync = ClockSync::new();
        // Agent 5 s ahead; 3 ms out, 1 ms back: the agent answered at 1.003 s.
        sync.add(1_000_000, 6_003_000, 1_004_000);
        let error = (sync.offset_us().expect("offset") - 5_000_000).unsigned_abs();
        assert!(error <= sync.uncertainty_us().expect("uncertainty"));
    }

    #[test]
    fn trusts_the_fastest_exchange() {
        let mut sync = ClockSync::new();
        sync.add(0, 5_010_000, 20_000); // queued: 20 ms, skewed
        sync.add(100_000, 5_100_500, 101_000); // clean: 1 ms
        sync.add(200_000, 5_215_000, 230_000); // queued again
        assert_eq!(sync.offset_us(), Some(5_000_000));
        assert_eq!(sync.uncertainty_us(), Some(500));
    }

    #[test]
    fn old_samples_age_out() {
        let mut sync = ClockSync::new();
        sync.add(0, 1_000, 0); // perfect but ancient
        for i in 1..=WINDOW as u64 {
            let t = i * 1_000_000;
            sync.add(t, t + 7_001, t + 2);
        }
        assert_eq!(sync.offset_us(), Some(7_000));
    }

    #[test]
    fn nonsense_is_ignored() {
        let mut sync = ClockSync::new();
        sync.add(10, 0, 5); // received before sent
        assert_eq!(sync.offset_us(), None);
        assert_eq!(sync.to_viewer_us(123), None);
    }

    #[test]
    fn same_clock_gives_zero_offset() {
        // Loopback: both ends read one counter.
        let mut sync = ClockSync::new();
        sync.add(1_000, 1_250, 1_500);
        assert_eq!(sync.offset_us(), Some(0));
    }
}
