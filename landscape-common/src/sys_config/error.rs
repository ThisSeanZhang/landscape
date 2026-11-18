use landscape_macro::LdApiError;

/// Errors from validating and persisting an online system configuration update.
#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum ConfigUpdateError {
    #[error(transparent)]
    #[api_error(transparent)]
    Dns(#[from] crate::dns::error::DnsServiceError),
    #[error(transparent)]
    #[api_error(transparent)]
    Metric(#[from] crate::metric::MetricError),
    #[error(transparent)]
    #[api_error(transparent)]
    LanHostname(#[from] super::LanHostnameError),
    #[error(transparent)]
    #[api_error(transparent)]
    Time(#[from] crate::sys_service::time_sync::TimeSyncError),
    #[error(transparent)]
    #[api_error(transparent)]
    SelfMonitor(#[from] super::self_monitor::SelfMonitorConfigError),
    #[error(transparent)]
    #[api_error(transparent)]
    Storage(#[from] crate::database::error::DbError),
}
