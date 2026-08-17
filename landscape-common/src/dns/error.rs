use hickory_proto::op::ResponseCode;
use landscape_macro::LdApiError;

use crate::config::FlowId;

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
