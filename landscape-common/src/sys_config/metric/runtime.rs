use super::config::{LandscapeMetricConfig, MetricMode};
use crate::metric::MetricError;
use crate::sys_config::{RuntimeConfigSource, runtime::repair_on_error};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricRuntimeConfig {
    pub mode: MetricMode,
    pub connect_second_window_minutes: u64,
    pub connect_1m_retention_days: u64,
    pub connect_1h_retention_days: u64,
    pub connect_1d_retention_days: u64,
    pub connect_summary_retention_days: u64,
    pub connect_summary_max_rows: u64,
    pub connect_db_max_bytes: u64,
    pub dns_retention_days: u64,
    pub dns_1m_retention_days: u64,
    pub dns_db_max_bytes: u64,
    pub write_batch_size: usize,
    pub write_flush_interval_secs: u64,
    pub cleanup_interval_secs: u64,
    pub cleanup_time_budget_ms: u64,
    pub cleanup_slice_window_secs: u64,
}

fn checked_db_max_mb(field: &'static str, value: u64) -> Result<u64, MetricError> {
    if value != 0 && !(crate::MIN_METRIC_DB_MAX_MB..=crate::MAX_METRIC_DB_MAX_MB).contains(&value) {
        return Err(MetricError::InvalidDbMaxMb { field, value });
    }
    Ok(value)
}

fn checked_cleanup_budget(value: u64) -> Result<u64, MetricError> {
    if !(1..=60).contains(&value) {
        return Err(MetricError::InvalidCleanupTimeBudget { value });
    }
    Ok(value)
}

fn db_max_bytes(field: &'static str, value: Option<u64>, default: u64) -> u64 {
    let Some(value) = value else {
        return default;
    };
    let repaired = if value == 0 {
        0
    } else {
        value.clamp(crate::MIN_METRIC_DB_MAX_MB, crate::MAX_METRIC_DB_MAX_MB)
    };
    let mb = repair_on_error(
        "metric",
        field,
        checked_db_max_mb(field, value),
        repaired,
        "clamped to valid range (MB)",
    );
    // Bounds are enforced before conversion, including for u64::MAX input.
    mb * 1024 * 1024
}

fn cleanup_budget_ms(value: Option<u64>) -> u64 {
    let Some(value) = value else {
        return crate::DEFAULT_METRIC_CLEANUP_TIME_BUDGET_MS;
    };
    let secs = repair_on_error(
        "metric",
        "cleanup_time_budget_secs",
        checked_cleanup_budget(value),
        value.clamp(1, 60),
        "clamped to valid range (seconds)",
    );
    secs * 1000
}

impl RuntimeConfigSource for LandscapeMetricConfig {
    type Runtime = MetricRuntimeConfig;
    type Error = MetricError;

    fn validate(&self) -> Result<(), Self::Error> {
        for (field, value) in
            [("connect_db_max_mb", self.connect_db_max_mb), ("dns_db_max_mb", self.dns_db_max_mb)]
        {
            if let Some(value) = value {
                checked_db_max_mb(field, value)?;
            }
        }
        if let Some(value) = self.cleanup_time_budget_secs {
            checked_cleanup_budget(value)?;
        }
        Ok(())
    }

    fn build_runtime(&self) -> Self::Runtime {
        let connect_1d_retention_days = self
            .connect_1d_retention_days
            .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1D_RETENTION_DAYS);

        MetricRuntimeConfig {
            mode: self.mode.clone().unwrap_or(crate::DEFAULT_METRIC_MODE),
            connect_second_window_minutes: self
                .connect_second_window_minutes
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_SECOND_WINDOW_MINUTES),
            connect_1m_retention_days: self
                .connect_1m_retention_days
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1M_RETENTION_DAYS),
            connect_1h_retention_days: self
                .connect_1h_retention_days
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1H_RETENTION_DAYS),
            connect_1d_retention_days,
            connect_summary_retention_days: self
                .connect_summary_retention_days
                .unwrap_or(connect_1d_retention_days),
            connect_summary_max_rows: self
                .connect_summary_max_rows
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_SUMMARY_MAX_ROWS),
            connect_db_max_bytes: db_max_bytes(
                "connect_db_max_mb",
                self.connect_db_max_mb,
                crate::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES,
            ),
            dns_retention_days: self
                .dns_retention_days
                .unwrap_or(crate::DEFAULT_DNS_METRIC_RETENTION_DAYS),
            dns_1m_retention_days: self
                .dns_1m_retention_days
                .unwrap_or(crate::DEFAULT_DNS_METRIC_1M_RETENTION_DAYS),
            dns_db_max_bytes: db_max_bytes(
                "dns_db_max_mb",
                self.dns_db_max_mb,
                crate::DEFAULT_DNS_METRIC_DB_MAX_BYTES,
            ),
            write_batch_size: self
                .write_batch_size
                .unwrap_or(crate::DEFAULT_METRIC_WRITE_BATCH_SIZE),
            write_flush_interval_secs: self
                .write_flush_interval_secs
                .unwrap_or(crate::DEFAULT_METRIC_WRITE_FLUSH_INTERVAL_SECS),
            cleanup_interval_secs: self
                .cleanup_interval_secs
                .unwrap_or(crate::DEFAULT_METRIC_CLEANUP_INTERVAL_SECS),
            cleanup_time_budget_ms: cleanup_budget_ms(self.cleanup_time_budget_secs),
            cleanup_slice_window_secs: self
                .cleanup_slice_window_secs
                .unwrap_or(crate::DEFAULT_METRIC_CLEANUP_SLICE_WINDOW_SECS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::MetricError;

    #[test]
    fn conversion_rejects_invalid_limits_with_domain_errors() {
        for value in [1, crate::MAX_METRIC_DB_MAX_MB + 1] {
            for dns in [false, true] {
                let mut config = LandscapeMetricConfig::default();
                if dns {
                    config.dns_db_max_mb = Some(value);
                } else {
                    config.connect_db_max_mb = Some(value);
                }
                assert!(matches!(config.to_runtime(), Err(MetricError::InvalidDbMaxMb { .. })));
            }
        }
        for value in [0, 61] {
            let config = LandscapeMetricConfig {
                cleanup_time_budget_secs: Some(value),
                ..Default::default()
            };
            assert!(matches!(
                config.to_runtime(),
                Err(MetricError::InvalidCleanupTimeBudget { .. })
            ));
        }
    }

    #[test]
    fn conversion_accepts_boundaries_and_preserves_units() {
        for value in [0, crate::MIN_METRIC_DB_MAX_MB, crate::MAX_METRIC_DB_MAX_MB] {
            for budget in [1, 60] {
                let config = LandscapeMetricConfig {
                    connect_db_max_mb: Some(value),
                    dns_db_max_mb: Some(value),
                    cleanup_time_budget_secs: Some(budget),
                    ..Default::default()
                };
                let runtime = config.to_runtime().unwrap();
                assert_eq!(runtime.connect_db_max_bytes, value * 1024 * 1024);
                assert_eq!(runtime.dns_db_max_bytes, value * 1024 * 1024);
                assert_eq!(runtime.cleanup_time_budget_ms, budget * 1000);
            }
        }
    }

    #[test]
    fn clearing_fields_restores_defaults_after_file_round_trip() {
        let custom = LandscapeMetricConfig {
            write_batch_size: Some(123),
            connect_1d_retention_days: Some(42),
            cleanup_time_budget_secs: Some(2),
            ..Default::default()
        };
        let runtime = custom.to_runtime().unwrap();
        assert_eq!(runtime.connect_summary_retention_days, 42);
        let cleared = LandscapeMetricConfig::default();
        let updated = cleared.to_runtime().unwrap();
        let reloaded: LandscapeMetricConfig =
            toml::from_str(&toml::to_string(&cleared).unwrap()).unwrap();
        assert_eq!(updated, reloaded.to_runtime().unwrap());
        assert_ne!(runtime, updated);
    }
    #[test]
    fn startup_repairs_each_invalid_field_and_preserves_valid_fields() {
        for budget in [0, 61] {
            let config = LandscapeMetricConfig {
                connect_db_max_mb: Some(1),
                dns_db_max_mb: Some(crate::MAX_METRIC_DB_MAX_MB + 1),
                cleanup_time_budget_secs: Some(budget),
                write_batch_size: Some(123),
                connect_1d_retention_days: Some(42),
                ..Default::default()
            };
            assert!(config.to_runtime().is_err());
            let runtime = config.build_runtime();
            assert_eq!(runtime.connect_db_max_bytes, 16 * 1024 * 1024);
            assert_eq!(runtime.dns_db_max_bytes, crate::MAX_METRIC_DB_MAX_MB * 1024 * 1024);
            assert_eq!(runtime.cleanup_time_budget_ms, if budget == 0 { 1000 } else { 60_000 });
            assert_eq!(runtime.write_batch_size, 123);
            assert_eq!(runtime.connect_summary_retention_days, 42);
            assert_eq!(config.cleanup_time_budget_secs, Some(budget));
        }
        let config = LandscapeMetricConfig {
            connect_db_max_mb: Some(0),
            dns_db_max_mb: Some(32),
            cleanup_time_budget_secs: Some(61),
            ..Default::default()
        };
        let runtime = config.build_runtime();
        assert_eq!(runtime.connect_db_max_bytes, 0);
        assert_eq!(runtime.dns_db_max_bytes, 32 * 1024 * 1024);
    }
    #[test]
    fn startup_clamps_capacity_boundaries_and_updates_reject_out_of_range() {
        for (value, mb) in [
            (0, 0),
            (1, 16),
            (15, 16),
            (16, 16),
            (crate::MAX_METRIC_DB_MAX_MB, crate::MAX_METRIC_DB_MAX_MB),
            (crate::MAX_METRIC_DB_MAX_MB + 1, crate::MAX_METRIC_DB_MAX_MB),
            (u64::MAX, crate::MAX_METRIC_DB_MAX_MB),
        ] {
            let config = LandscapeMetricConfig {
                connect_db_max_mb: Some(value),
                dns_db_max_mb: Some(value),
                ..Default::default()
            };
            let runtime = config.build_runtime();
            assert_eq!(runtime.connect_db_max_bytes, mb * 1024 * 1024);
            assert_eq!(runtime.dns_db_max_bytes, mb * 1024 * 1024);
            assert_eq!(config.to_runtime().is_ok(), value == mb);
        }
    }

    #[test]
    fn startup_clamps_budget_boundaries_and_keeps_missing_field_default() {
        for (value, ms) in [(0, 1000), (1, 1000), (60, 60_000), (61, 60_000), (u64::MAX, 60_000)] {
            let config = LandscapeMetricConfig {
                cleanup_time_budget_secs: Some(value),
                ..Default::default()
            };
            assert_eq!(config.build_runtime().cleanup_time_budget_ms, ms);
            assert_eq!(config.to_runtime().is_ok(), (1..=60).contains(&value));
        }
        let runtime = LandscapeMetricConfig::default().build_runtime();
        assert_eq!(runtime.connect_db_max_bytes, crate::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES);
        assert_eq!(runtime.dns_db_max_bytes, crate::DEFAULT_DNS_METRIC_DB_MAX_BYTES);
        assert_eq!(runtime.cleanup_time_budget_ms, crate::DEFAULT_METRIC_CLEANUP_TIME_BUDGET_MS);
    }
}
