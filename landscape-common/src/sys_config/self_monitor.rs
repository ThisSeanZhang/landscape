use super::RuntimeConfigSource;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeSelfMonitorConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub history_enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub retention_days: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfMonitorRuntimeConfig {
    pub enabled: bool,
    pub history_enabled: bool,
    pub retention_days: u64,
}

impl RuntimeConfigSource for LandscapeSelfMonitorConfig {
    type Runtime = SelfMonitorRuntimeConfig;
    type Error = SelfMonitorConfigError;
    fn validate(&self) -> Result<(), Self::Error> {
        if self.retention_days == Some(0) {
            return Err(SelfMonitorConfigError::InvalidRetention);
        }
        Ok(())
    }
    fn build_runtime(&self) -> Self::Runtime {
        SelfMonitorRuntimeConfig {
            enabled: self.enabled.unwrap_or(true),
            history_enabled: self.history_enabled.unwrap_or(true),
            retention_days: super::runtime::repair_on_error(
                "self_monitor",
                "retention_days",
                self.validate().map(|_| {
                    self.retention_days
                        .unwrap_or(crate::self_monitor::memory::DEFAULT_MEM_METRIC_RETENTION_DAYS)
                }),
                crate::self_monitor::memory::DEFAULT_MEM_METRIC_RETENTION_DAYS,
                "using default retention",
            ),
        }
    }
}

#[derive(thiserror::Error, Debug, landscape_macro::LdApiError)]
#[api_error(crate_path = "crate")]
pub enum SelfMonitorConfigError {
    #[error("self-monitor retention_days must be at least one")]
    #[api_error(id = "self_monitor.invalid_retention", status = 422)]
    InvalidRetention,
}
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetSelfMonitorConfigResponse {
    pub config: LandscapeSelfMonitorConfig,
    pub hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateSelfMonitorConfigRequest {
    pub config: LandscapeSelfMonitorConfig,
    pub expected_hash: String,
}
