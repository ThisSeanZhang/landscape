use hickory_proto::op::ResponseCode;
use landscape_macro::LdApiError;

use crate::config::{ConfigId, FlowId};
use crate::database::error::DbError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsServiceError {
    #[error("Invalid domain name '{domain}'")]
    #[api_error(id = "dns_domain.invalid", status = 400)]
    Invalid { domain: String },

    #[error("DNS flow '{0}' not found")]
    #[api_error(id = "dns_check.flow_not_found", status = 404)]
    FlowNotFound(FlowId),

    #[error("DNS cache refresh requires a matched upstream rule for '{0}'")]
    #[api_error(id = "dns_check.refresh_requires_rule", status = 409)]
    RefreshRequiresRule(String),

    #[error("DNS cache refresh is not available for redirected domain '{0}'")]
    #[api_error(id = "dns_check.refresh_redirected", status = 409)]
    RefreshRedirected(String),

    #[error("DNS cache refresh failed for '{0}'")]
    #[api_error(id = "dns_check.refresh_failed", status = 502)]
    RefreshFailed(String),

    #[error("DNS Protocol error: {0}")]
    #[api_error(id = "dns_service.protocol", status = 502)]
    Protocol(ResponseCode),

    #[error("Upstream timeout")]
    #[api_error(id = "dns_service.timeout", status = 504)]
    Timeout,

    #[error("Internal error: {0}")]
    #[api_error(id = "dns_service.internal", status = 500)]
    Internal(String),

    #[error("Io error: {0}")]
    #[api_error(id = "dns_service.io", status = 500)]
    Io(#[from] std::io::Error),

    #[error("Cache error: {0}")]
    #[api_error(id = "dns_service.cache", status = 500)]
    Cache(String),
}

pub type DnsResult<T> = Result<T, DnsServiceError>;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsProviderProfileError {
    #[error("Invalid DNS provider profile: {0}")]
    #[api_error(id = "dns_provider_profile.invalid", status = 422)]
    Invalid(String),

    #[error("DNS provider profile name '{0}' already exists")]
    #[api_error(id = "dns_provider_profile.name_conflict", status = 409)]
    NameConflict(String),

    #[error("Manual DNS provider cannot be used as a reusable DNS provider profile")]
    #[api_error(id = "dns_provider_profile.manual_not_allowed", status = 422)]
    ManualNotAllowed,

    #[error("DNS provider profile is still used by DDNS jobs: {0}")]
    #[api_error(id = "dns_provider_profile.in_use_by_ddns", status = 409)]
    InUseByDdns(String),

    #[error("DNS provider profile is still used by certificates: {0}")]
    #[api_error(id = "dns_provider_profile.in_use_by_certs", status = 409)]
    InUseByCerts(String),

    #[error("Provider credential validation failed: {0}")]
    #[api_error(id = "dns_provider_profile.credential_error", status = 422)]
    CredentialError(String),

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
}

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsRedirectError {
    #[error("DNS redirect rule '{0}' not found")]
    #[api_error(id = "dns_redirect.not_found", status = 404)]
    NotFound(ConfigId),
}

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsRuleError {
    #[error("DNS rule '{0}' not found")]
    #[api_error(id = "dns_rule.not_found", status = 404)]
    NotFound(ConfigId),
    #[error(
        "DNS rule '{0}' cannot be moved to another flow; delete it and create a new rule in the target flow instead"
    )]
    #[api_error(id = "dns_rule.cannot_change_flow", status = 400)]
    CannotChangeFlow(ConfigId),

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
}

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsUpstreamError {
    #[error("DNS upstream config '{0}' not found")]
    #[api_error(id = "dns_upstream.not_found", status = 404)]
    NotFound(ConfigId),
}
