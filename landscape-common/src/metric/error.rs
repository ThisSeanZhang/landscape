use landscape_macro::LdApiError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum MetricError {
    #[error("SQLite metric storage is unavailable in this build")]
    #[api_error(id = "metric.sqlite_unavailable", status = 422)]
    SqliteUnavailable,

    #[error(
        "{field} must be 0 (unlimited) or between {} and {} MB, got {value}",
        crate::MIN_METRIC_DB_MAX_MB,
        crate::MAX_METRIC_DB_MAX_MB
    )]
    #[api_error(id = "metric.invalid_db_max_mb", status = 422)]
    InvalidDbMaxMb { field: &'static str, value: u64 },

    #[error("cleanup_time_budget_secs must be between 1 and 60 seconds, got {value}")]
    #[api_error(id = "metric.invalid_cleanup_time_budget", status = 422)]
    InvalidCleanupTimeBudget { value: u64 },
}
