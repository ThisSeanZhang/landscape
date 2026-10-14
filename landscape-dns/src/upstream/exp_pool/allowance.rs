use std::future::Future;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub(crate) struct TimeAllowance {
    expiry: Instant,
}

impl TimeAllowance {
    pub(crate) fn new(allowance: Duration) -> Self {
        Self { expiry: Instant::now() + allowance }
    }

    pub(crate) fn time_left(&self) -> Option<Duration> {
        let now = Instant::now();
        self.expiry.checked_duration_since(now)
    }

    pub(crate) fn expires_at(&self) -> Instant {
        self.expiry
    }

    pub(crate) fn is_expired(&self) -> bool {
        self.time_left().is_none()
    }

    pub(crate) async fn complete_within<F: Future>(
        &self,
        future: F,
    ) -> Result<F::Output, hickory_resolver::net::NetError> {
        match tokio::time::timeout_at(self.expiry.into(), future).await {
            Ok(output) => Ok(output),
            Err(_spent) => Err(hickory_resolver::net::NetError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_left_shrinks_and_then_runs_dry() {
        let allowance = TimeAllowance::new(Duration::from_millis(150));

        let early = allowance.time_left().expect("a fresh allowance still has time");
        assert!(early > Duration::from_millis(100));
        assert!(early <= Duration::from_millis(150));

        std::thread::sleep(Duration::from_millis(200));
        assert!(allowance.time_left().is_none());
        assert!(allowance.is_expired());
    }

    #[tokio::test]
    async fn a_future_that_stalls_fails_with_timeout() {
        let allowance = TimeAllowance::new(Duration::from_millis(25));

        let answer =
            allowance.complete_within(tokio::time::sleep(Duration::from_millis(500))).await;

        assert!(matches!(answer, Err(hickory_resolver::net::NetError::Timeout)));
    }

    #[tokio::test]
    async fn a_future_that_beats_the_allowance_passes_through() {
        let allowance = TimeAllowance::new(Duration::from_millis(400));

        let answer = allowance.complete_within(async { vec![1, 2, 3] }).await;

        assert_eq!(answer.unwrap(), vec![1, 2, 3]);
    }
}
