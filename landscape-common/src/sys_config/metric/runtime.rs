use super::config::{ConnectMetricConfig, DnsMetricConfig, MetricStoreBackend, MetricStoreConfig};
use crate::metric::MetricError;
use crate::sys_config::{RuntimeConfigSource, runtime::repair_on_error};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetricStoreRuntimeConfig {
    pub backend: MetricStoreBackend,
    pub max_bytes: u64,
    pub write_flush_interval_secs: u64,
    pub cleanup_interval_secs: u64,
    pub cleanup_time_budget_ms: u64,
    pub cleanup_slice_window_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectMetricRuntimeConfig {
    pub enabled: bool,
    pub store: MetricStoreRuntimeConfig,
    pub second_window_minutes: u64,
    pub retention_1m_days: u64,
    pub retention_1h_days: u64,
    pub retention_1d_days: u64,
    pub summary_retention_days: u64,
    pub summary_max_rows: u64,
    pub write_batch_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsMetricRuntimeConfig {
    pub enabled: bool,
    pub store: MetricStoreRuntimeConfig,
    pub retention_days: u64,
    pub retention_1m_days: u64,
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

impl MetricStoreConfig {
    fn backend(&self) -> Result<MetricStoreBackend, MetricError> {
        let backend = self.backend.unwrap_or_default();
        if backend == MetricStoreBackend::Sqlite && !cfg!(feature = "metric-persistent") {
            return Err(MetricError::SqliteUnavailable);
        }
        Ok(backend)
    }

    fn validate(&self, field: &'static str) -> Result<(), MetricError> {
        self.backend()?;
        if let Some(cap) = self.max_mb {
            checked_db_max_mb(field, cap)?;
        }
        if let Some(budget) = self.cleanup_time_budget_secs {
            checked_cleanup_budget(budget)?;
        }
        Ok(())
    }

    fn build_runtime(&self, field: &'static str, default_cap: u64) -> MetricStoreRuntimeConfig {
        MetricStoreRuntimeConfig {
            backend: self.backend().unwrap_or_else(|error| {
                crate::sys_config::runtime::warn_repair(
                    "metric",
                    &format!("{}.backend", field.trim_end_matches(".max_mb")),
                    error,
                    "using available backend",
                    "memory",
                );
                MetricStoreBackend::Memory
            }),
            max_bytes: db_max_bytes(field, self.max_mb, default_cap),
            write_flush_interval_secs: self
                .write_flush_interval_secs
                .unwrap_or(crate::DEFAULT_METRIC_WRITE_FLUSH_INTERVAL_SECS),
            cleanup_interval_secs: self
                .cleanup_interval_secs
                .unwrap_or(crate::DEFAULT_METRIC_CLEANUP_INTERVAL_SECS),
            cleanup_slice_window_secs: self
                .cleanup_slice_window_secs
                .unwrap_or(crate::DEFAULT_METRIC_CLEANUP_SLICE_WINDOW_SECS),
            cleanup_time_budget_ms: cleanup_budget_ms(self.cleanup_time_budget_secs),
        }
    }
}

impl RuntimeConfigSource for ConnectMetricConfig {
    type Runtime = ConnectMetricRuntimeConfig;
    type Error = MetricError;
    fn validate(&self) -> Result<(), MetricError> {
        self.store.validate("connect.store.max_mb")
    }
    fn build_runtime(&self) -> Self::Runtime {
        let retention_1d_days =
            self.retention_1d_days.unwrap_or(crate::DEFAULT_METRIC_CONNECT_1D_RETENTION_DAYS);
        ConnectMetricRuntimeConfig {
            enabled: self.enabled.unwrap_or(true),
            store: self
                .store
                .build_runtime("connect.store.max_mb", crate::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES),
            second_window_minutes: self
                .second_window_minutes
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_SECOND_WINDOW_MINUTES),
            retention_1m_days: self
                .retention_1m_days
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1M_RETENTION_DAYS),
            retention_1h_days: self
                .retention_1h_days
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1H_RETENTION_DAYS),
            retention_1d_days,
            summary_retention_days: self.summary_retention_days.unwrap_or(retention_1d_days),
            summary_max_rows: self
                .summary_max_rows
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_SUMMARY_MAX_ROWS),
            write_batch_size: self
                .write_batch_size
                .unwrap_or(crate::DEFAULT_METRIC_WRITE_BATCH_SIZE),
        }
    }
}

impl RuntimeConfigSource for DnsMetricConfig {
    type Runtime = DnsMetricRuntimeConfig;
    type Error = MetricError;
    fn validate(&self) -> Result<(), MetricError> {
        self.store.validate("dns.store.max_mb")
    }
    fn build_runtime(&self) -> Self::Runtime {
        DnsMetricRuntimeConfig {
            enabled: self.enabled.unwrap_or(true),
            store: self
                .store
                .build_runtime("dns.store.max_mb", crate::DEFAULT_DNS_METRIC_DB_MAX_BYTES),
            retention_days: self.retention_days.unwrap_or(crate::DEFAULT_DNS_METRIC_RETENTION_DAYS),
            retention_1m_days: self
                .retention_1m_days
                .unwrap_or(crate::DEFAULT_DNS_METRIC_1M_RETENTION_DAYS),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys_config::LandscapeConfig;

    #[test]
    fn store_limits_repair_at_startup_and_reject_invalid_edits() {
        for (value, mb) in [
            (0, 0),
            (1, 16),
            (15, 16),
            (16, 16),
            (crate::MAX_METRIC_DB_MAX_MB, crate::MAX_METRIC_DB_MAX_MB),
            (u64::MAX, crate::MAX_METRIC_DB_MAX_MB),
        ] {
            for (budget, ms) in
                [(0, 1000), (1, 1000), (60, 60_000), (61, 60_000), (u64::MAX, 60_000)]
            {
                let store = MetricStoreConfig {
                    max_mb: Some(value),
                    cleanup_time_budget_secs: Some(budget),
                    ..Default::default()
                };
                let connect = ConnectMetricConfig {
                    store: store.clone(),
                    write_batch_size: Some(123),
                    retention_1d_days: Some(42),
                    ..Default::default()
                };
                let dns = DnsMetricConfig { store, ..Default::default() };
                let valid = value == mb && (1..=60).contains(&budget);
                assert_eq!(connect.to_runtime().is_ok(), valid);
                assert_eq!(dns.to_runtime().is_ok(), valid);
                let runtime = connect.build_runtime();
                assert_eq!(runtime.store.max_bytes, mb * 1024 * 1024);
                assert_eq!(runtime.store.cleanup_time_budget_ms, ms);
                assert_eq!(runtime.write_batch_size, 123);
                assert_eq!(runtime.summary_retention_days, 42);
                assert_eq!(runtime.store, dns.build_runtime().store);
            }
        }
    }

    #[test]
    fn sqlite_requires_persistence_and_file_loading_uses_the_available_backend() {
        let store = MetricStoreConfig {
            backend: Some(MetricStoreBackend::Sqlite),
            ..Default::default()
        };
        let connect = ConnectMetricConfig { store: store.clone(), ..Default::default() };
        let dns = DnsMetricConfig { store, ..Default::default() };
        assert_eq!(connect.to_runtime().is_ok(), cfg!(feature = "metric-persistent"));
        assert_eq!(dns.to_runtime().is_ok(), cfg!(feature = "metric-persistent"));
        assert_eq!(connect.build_runtime().store.backend, MetricStoreBackend::default());
        assert_eq!(dns.build_runtime().store.backend, MetricStoreBackend::default());
    }

    #[test]
    fn each_pipeline_uses_its_own_defaults() {
        let connect = ConnectMetricConfig::default().to_runtime().unwrap();
        let dns = DnsMetricConfig::default().to_runtime().unwrap();
        assert!(connect.enabled && dns.enabled);
        assert_eq!(connect.store.max_bytes, crate::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES);
        assert_eq!(dns.store.max_bytes, crate::DEFAULT_DNS_METRIC_DB_MAX_BYTES);
        assert_eq!(dns.store.cleanup_time_budget_ms, crate::DEFAULT_METRIC_CLEANUP_TIME_BUDGET_MS);
    }

    #[test]
    fn legacy_mode_and_shared_options_survive_canonical_round_trip() {
        for (mode, enabled, backend, history) in [
            ("off", false, MetricStoreBackend::default(), false),
            ("memory", true, MetricStoreBackend::Memory, false),
            ("duckdb", true, MetricStoreBackend::default(), true),
            ("persistent", true, MetricStoreBackend::default(), true),
        ] {
            let old = format!(
                "[metric]\nmode='{mode}'\nwrite_flush_interval_secs=12\n[metric.dns.store]\nwrite_flush_interval_secs=45\n"
            );
            let config: LandscapeConfig = toml::from_str(&old).unwrap();
            let connect = config.metric.connect.build_runtime();
            let dns = config.metric.dns.build_runtime();
            assert_eq!(connect.enabled, enabled);
            assert_eq!(dns.enabled, enabled);
            assert_eq!(connect.store.backend, backend);
            assert_eq!(dns.store.backend, backend);
            assert_eq!(connect.store.write_flush_interval_secs, 12);
            assert_eq!(dns.store.write_flush_interval_secs, 45);
            assert_eq!(config.self_monitor.build_runtime().history_enabled, history);
            assert!(config.self_monitor.build_runtime().enabled);
            let saved = toml::to_string(&config).unwrap();
            let reloaded: LandscapeConfig = toml::from_str(&saved).unwrap();
            assert_eq!(reloaded.metric, config.metric);
            assert_eq!(reloaded.self_monitor, config.self_monitor);
            assert_eq!(
                toml::from_str::<toml::Table>(&saved).unwrap()["metric"].as_table().unwrap().len(),
                2
            );
        }
        let explicit:LandscapeConfig=toml::from_str("[metric]\nmode='off'\n[metric.connect]\nenabled=true\n[self_monitor]\nhistory_enabled=true").unwrap();
        assert!(explicit.metric.connect.build_runtime().enabled);
        assert!(!explicit.metric.dns.build_runtime().enabled);
        assert!(explicit.self_monitor.build_runtime().history_enabled);
    }
}
