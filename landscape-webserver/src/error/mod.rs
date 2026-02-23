use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use landscape_common::api_response::LandscapeApiResp as CommonLandscapeApiResp;
use landscape_common::config::dns::DnsRuleError;
use landscape_common::config::geo::{GeoIpError, GeoSiteError};
use landscape_common::config::nat::StaticNatError;
use landscape_common::dhcp::DhcpError;
use landscape_common::dns::redirect::DnsRedirectError;
use landscape_common::dns::upstream::DnsUpstreamError;
use landscape_common::enrolled_device::EnrolledDeviceError;
use landscape_common::error::{LdApiErrorInfo, LdError};
use landscape_common::firewall::blacklist::FirewallBlacklistError;
use landscape_common::firewall::FirewallRuleError;
use landscape_common::flow::FlowRuleError;
use landscape_common::ip_mark::DstIpRuleError;
use landscape_common::service::ServiceConfigError;

use crate::api::LandscapeApiResp;
use crate::auth::error::AuthError;
use crate::docker::error::DockerError;

#[derive(thiserror::Error, Debug)]
pub enum LandscapeApiError {
    // Domain errors — each carries its own error_id and HTTP status
    #[error(transparent)]
    DnsRule(#[from] DnsRuleError),
    #[error(transparent)]
    DnsUpstream(#[from] DnsUpstreamError),
    #[error(transparent)]
    DnsRedirect(#[from] DnsRedirectError),
    #[error(transparent)]
    FlowRule(#[from] FlowRuleError),
    #[error(transparent)]
    FirewallRule(#[from] FirewallRuleError),
    #[error(transparent)]
    FirewallBlacklist(#[from] FirewallBlacklistError),
    #[error(transparent)]
    Dhcp(#[from] DhcpError),
    #[error(transparent)]
    GeoSite(#[from] GeoSiteError),
    #[error(transparent)]
    GeoIp(#[from] GeoIpError),
    #[error(transparent)]
    StaticNat(#[from] StaticNatError),
    #[error(transparent)]
    DstIpRule(#[from] DstIpRuleError),
    #[error(transparent)]
    EnrolledDevice(#[from] EnrolledDeviceError),
    #[error(transparent)]
    ServiceConfig(#[from] ServiceConfigError),
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Docker(#[from] DockerError),

    // Generic errors
    #[error("Internal error: {0}")]
    Internal(#[from] LdError),
    #[error("Invalid JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid request body: {0}")]
    JsonRejection(JsonRejection),
}

impl LandscapeApiError {
    pub fn error_id(&self) -> &str {
        match self {
            Self::DnsRule(e) => e.error_id(),
            Self::DnsUpstream(e) => e.error_id(),
            Self::DnsRedirect(e) => e.error_id(),
            Self::FlowRule(e) => e.error_id(),
            Self::FirewallRule(e) => e.error_id(),
            Self::FirewallBlacklist(e) => e.error_id(),
            Self::Dhcp(e) => e.error_id(),
            Self::GeoSite(e) => e.error_id(),
            Self::GeoIp(e) => e.error_id(),
            Self::StaticNat(e) => e.error_id(),
            Self::DstIpRule(e) => e.error_id(),
            Self::EnrolledDevice(e) => e.error_id(),
            Self::ServiceConfig(e) => e.error_id(),
            Self::Auth(e) => e.error_id(),
            Self::Docker(e) => e.error_id(),
            Self::Internal(e) => match e {
                LdError::ConfigConflict => "config.conflict",
                _ => "internal.error",
            },
            Self::JsonError(_) => "request.invalid_json",
            Self::JsonRejection(_) => "request.invalid_body",
        }
    }

    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::DnsRule(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DnsUpstream(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DnsRedirect(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::FlowRule(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::FirewallRule(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::FirewallBlacklist(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Dhcp(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::GeoSite(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::GeoIp(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::StaticNat(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DstIpRule(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::EnrolledDevice(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::ServiceConfig(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Auth(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Docker(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Internal(e) => match e {
                LdError::ConfigConflict => StatusCode::CONFLICT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            },
            Self::JsonError(_) => StatusCode::BAD_REQUEST,
            Self::JsonRejection(r) => r.status(),
        }
    }

    pub fn error_args(&self) -> serde_json::Value {
        match self {
            Self::DnsRule(e) => e.error_args(),
            Self::DnsUpstream(e) => e.error_args(),
            Self::DnsRedirect(e) => e.error_args(),
            Self::FlowRule(e) => e.error_args(),
            Self::FirewallRule(e) => e.error_args(),
            Self::FirewallBlacklist(e) => e.error_args(),
            Self::Dhcp(e) => e.error_args(),
            Self::GeoSite(e) => e.error_args(),
            Self::GeoIp(e) => e.error_args(),
            Self::StaticNat(e) => e.error_args(),
            Self::DstIpRule(e) => e.error_args(),
            Self::EnrolledDevice(e) => e.error_args(),
            Self::ServiceConfig(e) => e.error_args(),
            Self::Auth(e) => e.error_args(),
            Self::Docker(e) => e.error_args(),
            Self::Internal(_) | Self::JsonError(_) | Self::JsonRejection(_) => {
                serde_json::json!({})
            }
        }
    }
}

impl IntoResponse for LandscapeApiError {
    fn into_response(self) -> axum::response::Response {
        let status = self.http_status();
        let args = self.error_args();
        let resp =
            CommonLandscapeApiResp::<()>::error_with_args(self.error_id(), self.to_string(), args);
        (status, Json(resp)).into_response()
    }
}

pub type LandscapeApiResult<T> = Result<LandscapeApiResp<T>, LandscapeApiError>;
