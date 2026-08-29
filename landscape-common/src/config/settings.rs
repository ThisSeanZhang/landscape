use std::{net::IpAddr, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::service::ServiceConfigError;
use crate::sys_service::{
    gateway::settings::LandscapeGatewayConfig, lan_hostname::LandscapeLanHostnameConfig,
};

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
    Duckdb,
    #[default]
    Persistent,
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
    pub connect_summary_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub connect_summary_max_rows: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub connect_db_max_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dns_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dns_1m_retention_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub dns_db_max_mb: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub write_batch_size: Option<usize>,
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

impl LandscapeMetricConfig {
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        for (name, value) in
            [("connect_db_max_mb", self.connect_db_max_mb), ("dns_db_max_mb", self.dns_db_max_mb)]
        {
            if let Some(v) = value {
                if v != 0
                    && !(crate::MIN_METRIC_DB_MAX_MB..=crate::MAX_METRIC_DB_MAX_MB).contains(&v)
                {
                    return Err(ServiceConfigError::InvalidConfig {
                        reason: format!(
                            "{name} must be 0 (unlimited) or between {} and {} MB, got {v}",
                            crate::MIN_METRIC_DB_MAX_MB,
                            crate::MAX_METRIC_DB_MAX_MB,
                        ),
                    });
                }
            }
        }
        if let Some(v) = self.cleanup_time_budget_secs {
            if !(1..=60).contains(&v) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "cleanup_time_budget_secs must be between 1 and 60 seconds, got {v}"
                    ),
                });
            }
        }
        Ok(())
    }
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
    #[serde(default, alias = "hostname_registry")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub lan_hostname: LandscapeLanHostnameConfig,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{cleanup_budget_secs_to_ms, metric_db_max_mb_to_bytes};

    #[test]
    fn validate_accepts_default_and_unlimited_caps() {
        assert!(LandscapeMetricConfig::default().validate().is_ok());
        let unlimited = LandscapeMetricConfig {
            connect_db_max_mb: Some(0),
            dns_db_max_mb: Some(0),
            ..Default::default()
        };
        assert!(unlimited.validate().is_ok());
    }

    #[test]
    fn validate_accepts_min_and_max_caps() {
        let config = LandscapeMetricConfig {
            connect_db_max_mb: Some(crate::MIN_METRIC_DB_MAX_MB),
            dns_db_max_mb: Some(crate::MAX_METRIC_DB_MAX_MB),
            cleanup_time_budget_secs: Some(1),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_caps_below_minimum() {
        let config = LandscapeMetricConfig {
            connect_db_max_mb: Some(crate::MIN_METRIC_DB_MAX_MB - 1),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = LandscapeMetricConfig {
            dns_db_max_mb: Some(crate::MIN_METRIC_DB_MAX_MB - 1),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_caps_above_maximum() {
        let config = LandscapeMetricConfig {
            connect_db_max_mb: Some(crate::MAX_METRIC_DB_MAX_MB + 1),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = LandscapeMetricConfig {
            dns_db_max_mb: Some(crate::MAX_METRIC_DB_MAX_MB + 1),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_cleanup_budget() {
        let config = LandscapeMetricConfig {
            cleanup_time_budget_secs: Some(0),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_cleanup_budget_above_maximum() {
        let config = LandscapeMetricConfig {
            cleanup_time_budget_secs: Some(61),
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config = LandscapeMetricConfig {
            cleanup_time_budget_secs: Some(60),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

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
