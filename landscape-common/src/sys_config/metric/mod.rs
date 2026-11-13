pub mod api;
pub mod config;
pub mod runtime;

pub use api::{GetMetricConfigResponse, UpdateMetricConfigRequest};
pub use config::{LandscapeMetricConfig, MetricMode};
pub use runtime::MetricRuntimeConfig;

pub fn metric_db_max_mb_to_bytes(mb: u64) -> u64 {
    if mb == 0 {
        return 0;
    }
    mb.max(crate::MIN_METRIC_DB_MAX_MB).saturating_mul(1024 * 1024)
}

pub fn cleanup_budget_secs_to_ms(secs: u64) -> u64 {
    secs.max(1).saturating_mul(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_db_max_mb_to_bytes_keeps_unlimited_and_clamps_small_values() {
        assert_eq!(metric_db_max_mb_to_bytes(0), 0);
        assert_eq!(metric_db_max_mb_to_bytes(crate::MIN_METRIC_DB_MAX_MB), 16 * 1024 * 1024);
        assert_eq!(metric_db_max_mb_to_bytes(crate::MIN_METRIC_DB_MAX_MB - 1), 16 * 1024 * 1024);
        assert_eq!(metric_db_max_mb_to_bytes(512), 512 * 1024 * 1024);
    }

    #[test]
    fn cleanup_budget_secs_to_ms_clamps_zero() {
        assert_eq!(cleanup_budget_secs_to_ms(0), 1000);
        assert_eq!(cleanup_budget_secs_to_ms(2), 2000);
        assert_eq!(cleanup_budget_secs_to_ms(3600), 3600 * 1000);
    }
}
