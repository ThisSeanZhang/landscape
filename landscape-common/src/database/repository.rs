use crate::utils::time::get_f64_timestamp;

/// Minimum step between consecutive `update_at` versions (1 ms).
/// `get_f64_timestamp()` returns integer milliseconds, so a step of `1.0` bumps
/// the version by exactly 1 ms; two same-millisecond writes would otherwise
/// produce the same version and let a stale client pass the lock check.
const MIN_TS_STEP: f64 = 1.0;

/// Extracts the ID and `update_at` timestamp from a domain type.
///
/// `update_at` doubles as the optimistic-lock version: every persisted write
/// refreshes it to a value strictly greater than the stored one, so clients
/// holding a stale value always fail `checked_upsert` with `DbError::Conflict`.
/// Clients must echo the `update_at` they received back unchanged.
///
/// `next_update_at`/`refresh_update_at` keep the version policy (strictly
/// increasing, monotonic across clock rollback) in one place so storage layers
/// (e.g. `ConfigStore`) never re-implement it.
pub trait LandscapeDBStore<Id> {
    fn get_id(&self) -> Id;
    fn get_update_at(&self) -> f64;
    fn set_update_at(&mut self, ts: f64);

    /// Next strictly-increasing version: at least `MIN_TS_STEP` above the
    /// current one, so clock skew/rollback (`now` behind the stored version)
    /// and same-millisecond writes can never produce a colliding version.
    fn next_update_at(&self, now: f64) -> f64 {
        now.max(self.get_update_at() + MIN_TS_STEP)
    }

    /// Convenience wrapper using the system clock.
    fn refresh_update_at(&mut self) {
        self.set_update_at(self.next_update_at(get_f64_timestamp()));
    }
}

#[cfg(test)]
mod tests {
    use super::LandscapeDBStore;

    struct V(f64);

    impl LandscapeDBStore<String> for V {
        fn get_id(&self) -> String {
            String::new()
        }

        fn get_update_at(&self) -> f64 {
            self.0
        }

        fn set_update_at(&mut self, ts: f64) {
            self.0 = ts;
        }
    }

    #[test]
    fn next_update_at_stays_strictly_above_stored_version_on_clock_rollback() {
        let v = V(1000.0);
        assert_eq!(v.next_update_at(900.0), 1001.0);
    }

    #[test]
    fn next_update_at_bumps_same_millisecond_write() {
        let v = V(1000.0);
        assert_eq!(v.next_update_at(1000.0), 1001.0);
    }

    #[test]
    fn next_update_at_uses_clock_when_ahead() {
        let v = V(1000.0);
        assert_eq!(v.next_update_at(2000.0), 2000.0);
    }
}
