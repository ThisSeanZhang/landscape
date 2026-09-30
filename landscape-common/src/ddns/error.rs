use landscape_macro::LdApiError;

use crate::config::ConfigId;
use crate::database::error::DbError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DdnsError {
    #[error("DDNS job '{0}' not found")]
    #[api_error(id = "ddns.job_not_found", status = 404)]
    JobNotFound(ConfigId),

    #[error("Invalid DDNS job config: {0}")]
    #[api_error(id = "ddns.invalid_config", status = 422)]
    InvalidConfig(String),

    #[error("DNS provider profile '{0}' not found")]
    #[api_error(id = "ddns.provider_profile_not_found", status = 404)]
    ProviderProfileNotFound(ConfigId),

    #[error("DNS provider is not available: {0}")]
    #[api_error(id = "ddns.provider_unavailable", status = 502)]
    ProviderUnavailable(String),

    #[error("Cannot access DNS zone: {0}")]
    #[api_error(id = "ddns.zone_access_denied", status = 422)]
    ZoneAccessDenied(String),

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
}
