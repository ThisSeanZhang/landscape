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
        if elapsed >= self.duration {
            Duration::from_secs(0)
        } else {
            self.duration - elapsed
        }
    }
}

pub const MILL_A_DAY: u32 = 1000 * 60 * 60 * 24;

pub fn get_f64_timestamp() -> f64 {
    const MILLIS_PER_SEC: u64 = 1_000;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time is before UNIX_EPOCH");

    (time.as_secs() as f64) * (MILLIS_PER_SEC as f64) + (time.subsec_millis() as f64)
}

#[cfg(test)]
mod tests {
    use super::get_f64_timestamp;

    #[test]
    fn timestamp_uses_unix_milliseconds() {
        assert!(get_f64_timestamp() > 1_000_000_000_000.0);
    }
}
