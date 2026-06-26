use std::{net::IpAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::gateway::settings::LandscapeGatewayConfig;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeAuthConfig {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub admin_user: Option<String>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub admin_pass: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeWebConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable = false))]
    pub web_root: Option<PathBuf>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub port: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub https_port: Option<u16>,
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable = false))]
    pub address: Option<IpAddr>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeLogConfig {
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, nullable = false))]
    pub log_path: Option<PathBuf>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub debug: Option<bool>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub log_output_in_terminal: Option<bool>,
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub max_log_files: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeStoreConfig {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub database_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum MetricMode {
    Off,
    Memory,
    #[default]
    Duckdb,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeMetricConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub mode: Option<MetricMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub connect_second_window_minutes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub connect_1m_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub connect_1h_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub connect_1d_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dns_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub write_batch_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub write_flush_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub db_max_memory_mb: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub db_max_threads: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cleanup_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cleanup_time_budget_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cleanup_slice_window_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeDnsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cache_capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cache_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub negative_cache_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub doh_listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub doh_http_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub lan_suffix: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeUIConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub language: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub timezone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub theme: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeTimeConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub servers: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub sync_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub step_threshold_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub samples_per_server: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeConfig {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub auth: LandscapeAuthConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub web: LandscapeWebConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub log: LandscapeLogConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub store: LandscapeStoreConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub metric: LandscapeMetricConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub dns: LandscapeDnsConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub ui: LandscapeUIConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub time: LandscapeTimeConfig,
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub gateway: LandscapeGatewayConfig,
}
