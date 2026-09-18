//! The clock that capture timestamps are measured on.
//!
//! Capture times come from DXGI's `LastPresentTime`, a performance-counter
//! value, so anything compared with them must read the same counter: the agent
//! answers the viewer's clock probes with [`now_us`], and the viewer measures
//! its own side with [`now_us`] too. On one machine both ends then share a
//! clock exactly, which makes loopback runs a check on the offset estimate.
//!
//! The epoch is arbitrary (boot time on Windows, process start elsewhere); only
//! differences and offsets between machines mean anything.

/// Microseconds on the capture clock.
#[cfg(windows)]
pub fn now_us() -> u64 {
    use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};

    let mut ticks = 0i64;
    let mut frequency = 0i64;
    // Neither call can fail on any Windows that runs this code.
    unsafe {
        let _ = QueryPerformanceCounter(&mut ticks);
        let _ = QueryPerformanceFrequency(&mut frequency);
    }
    ticks_to_us(ticks, frequency)
}

/// Microseconds on the capture clock.
#[cfg(not(windows))]
pub fn now_us() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_micros() as u64
}

/// Performance-counter ticks to microseconds, without overflow.
pub(crate) fn ticks_to_us(ticks: i64, frequency: i64) -> u64 {
    if frequency <= 0 {
        return 0;
    }
    let us = (i128::from(ticks) * 1_000_000) / i128::from(frequency);
    us.clamp(0, i128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_monotonic() {
        let a = now_us();
        let b = now_us();
        assert!(b >= a);
    }

    #[test]
    fn converts_ticks_without_overflow() {
        assert_eq!(ticks_to_us(10_000_000, 10_000_000), 1_000_000);
        assert_eq!(ticks_to_us(i64::MAX, 10_000_000), (i64::MAX as u64) / 10);
        assert_eq!(ticks_to_us(-5, 10_000_000), 0);
        assert_eq!(ticks_to_us(5, 0), 0);
    }
}
