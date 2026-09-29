use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};

use libc::{CLOCK_BOOTTIME, clock_gettime, timespec};
use tokio::time::{Duration, Instant};

pub struct LdCountdown {
    start: Instant,
    duration: Duration,
}

impl LdCountdown {
    pub fn new(duration: Duration) -> Self {
        Self { start: Instant::now(), duration }
    }

    pub fn remaining(&self) -> Duration {
        let elapsed = self.start.elapsed();
        if elapsed >= self.duration { Duration::from_secs(0) } else { self.duration - elapsed }
    }
}

pub const MILL_A_DAY: u32 = 1000 * 60 * 60 * 24;

/// The single source of truth for wall-clock time. Change time semantics here.
#[inline]
pub fn now() -> SystemTime {
    SystemTime::now()
}

/// Current Unix timestamp in milliseconds. Every caller that needs "now" should converge here.
#[inline]
pub fn now_ms() -> u64 {
    now().duration_since(UNIX_EPOCH).map(|duration| duration.as_millis() as u64).unwrap_or(0)
}

/// Current Unix timestamp in nanoseconds.
#[inline]
pub fn now_ns() -> u64 {
    now().duration_since(UNIX_EPOCH).map(|duration| duration.as_nanos() as u64).unwrap_or(0)
}

/// `CLOCK_BOOTTIME` in nanoseconds (since boot, including suspend); used for kernel/eBPF-side scheduling.
pub fn get_boot_time_ns() -> Result<u64, i32> {
    let mut ts: timespec = unsafe { mem::zeroed() };

    let result = unsafe { clock_gettime(CLOCK_BOOTTIME, &mut ts) };

    if result == 0 {
        Ok((ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64))
    } else {
        Err(unsafe { *libc::__errno_location() })
    }
}

/// Compatibility shim for legacy `f64` millisecond callers and serde `default`; delegates to [`now_ms`].
pub fn get_f64_timestamp() -> f64 {
    now_ms() as f64
}

#[cfg(test)]
mod tests {
    use super::{get_boot_time_ns, get_f64_timestamp, now_ms, now_ns};

    #[test]
    fn timestamp_uses_unix_milliseconds() {
        assert!(get_f64_timestamp() > 1_000_000_000_000.0);
    }

    #[test]
    fn now_ms_and_ns_are_consistent() {
        let ms = now_ms();
        assert!(ms > 1_000_000_000_000);
        assert!(now_ns() / 1_000_000 >= ms);
    }

    #[test]
    fn boot_time_is_available() {
        assert!(get_boot_time_ns().unwrap() > 0);
    }
}
