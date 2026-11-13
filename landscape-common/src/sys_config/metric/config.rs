use serde::{Deserialize, Serialize};

use crate::service::ServiceConfigError;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum MetricMode {
    Off,
    Memory,
    #[serde(alias = "duckdb")]
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
            if let Some(v) = value
                && v != 0
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
        if let Some(v) = self.cleanup_time_budget_secs
            && !(1..=60).contains(&v)
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "cleanup_time_budget_secs must be between 1 and 60 seconds, got {v}"
                ),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
