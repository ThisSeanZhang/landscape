use serde::{Deserialize, Serialize};

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum LegacyMetricMode {
    Off,
    Memory,
    #[serde(alias = "duckdb")]
    Persistent,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MetricStoreBackend {
    #[cfg_attr(not(feature = "metric-persistent"), default)]
    Memory,
    #[cfg_attr(feature = "metric-persistent", default)]
    Sqlite,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MetricStoreConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub backend: Option<MetricStoreBackend>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub max_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub write_flush_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cleanup_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cleanup_time_budget_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cleanup_slice_window_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConnectMetricConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub second_window_minutes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub retention_1m_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub retention_1h_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub retention_1d_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub summary_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub summary_max_rows: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub write_batch_size: Option<usize>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub store: MetricStoreConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsMetricConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub retention_1m_days: Option<u64>,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub store: MetricStoreConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(from = "MetricFile")]
pub struct LandscapeMetricConfig {
    pub connect: ConnectMetricConfig,
    pub dns: DnsMetricConfig,
    #[serde(skip)]
    #[cfg_attr(feature = "openapi", schema(ignore))]
    pub(crate) legacy_history_enabled: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct MetricFile {
    connect: ConnectMetricConfig,
    dns: DnsMetricConfig,
    mode: Option<LegacyMetricMode>,
    connect_second_window_minutes: Option<u64>,
    connect_1m_retention_days: Option<u64>,
    connect_1h_retention_days: Option<u64>,
    connect_1d_retention_days: Option<u64>,
    connect_summary_retention_days: Option<u64>,
    connect_summary_max_rows: Option<u64>,
    connect_db_max_mb: Option<u64>,
    dns_retention_days: Option<u64>,
    dns_1m_retention_days: Option<u64>,
    dns_db_max_mb: Option<u64>,
    write_batch_size: Option<usize>,
    write_flush_interval_secs: Option<u64>,
    cleanup_interval_secs: Option<u64>,
    cleanup_time_budget_secs: Option<u64>,
    cleanup_slice_window_secs: Option<u64>,
}

impl From<MetricFile> for LandscapeMetricConfig {
    fn from(file: MetricFile) -> Self {
        let enabled = file.mode.as_ref().map(|m| *m != LegacyMetricMode::Off);
        let backend = file.mode.as_ref().and_then(|m| match m {
            LegacyMetricMode::Off => None,
            LegacyMetricMode::Memory => Some(MetricStoreBackend::Memory),
            LegacyMetricMode::Persistent => Some(MetricStoreBackend::Sqlite),
        });
        let store = |nested: MetricStoreConfig, max_mb: Option<u64>| MetricStoreConfig {
            backend: nested.backend.or(backend),
            max_mb: nested.max_mb.or(max_mb),
            write_flush_interval_secs: nested
                .write_flush_interval_secs
                .or(file.write_flush_interval_secs),
            cleanup_interval_secs: nested.cleanup_interval_secs.or(file.cleanup_interval_secs),
            cleanup_time_budget_secs: nested
                .cleanup_time_budget_secs
                .or(file.cleanup_time_budget_secs),
            cleanup_slice_window_secs: nested
                .cleanup_slice_window_secs
                .or(file.cleanup_slice_window_secs),
        };
        Self {
            legacy_history_enabled: file.mode.map(|mode| mode == LegacyMetricMode::Persistent),
            connect: ConnectMetricConfig {
                enabled: file.connect.enabled.or(enabled),
                second_window_minutes: file
                    .connect
                    .second_window_minutes
                    .or(file.connect_second_window_minutes),
                retention_1m_days: file
                    .connect
                    .retention_1m_days
                    .or(file.connect_1m_retention_days),
                retention_1h_days: file
                    .connect
                    .retention_1h_days
                    .or(file.connect_1h_retention_days),
                retention_1d_days: file
                    .connect
                    .retention_1d_days
                    .or(file.connect_1d_retention_days),
                summary_retention_days: file
                    .connect
                    .summary_retention_days
                    .or(file.connect_summary_retention_days),
                summary_max_rows: file.connect.summary_max_rows.or(file.connect_summary_max_rows),
                write_batch_size: file.connect.write_batch_size.or(file.write_batch_size),
                store: store(file.connect.store, file.connect_db_max_mb),
            },
            dns: DnsMetricConfig {
                enabled: file.dns.enabled.or(enabled),
                retention_days: file.dns.retention_days.or(file.dns_retention_days),
                retention_1m_days: file.dns.retention_1m_days.or(file.dns_1m_retention_days),
                store: store(file.dns.store, file.dns_db_max_mb),
            },
        }
    }
}
