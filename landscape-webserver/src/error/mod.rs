use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use landscape_common::api_response::LandscapeApiResp as CommonLandscapeApiResp;
use landscape_common::cert::CertError;
use landscape_common::config::InitConfigError;
use landscape_common::config_service::enrolled_device::EnrolledDeviceError;
use landscape_common::config_service::geo::GeoError;
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::ddns::DdnsError;
use landscape_common::dns::error::DnsServiceError;
use landscape_common::dns::provider_profile::DnsProviderProfileError;
use landscape_common::dns::redirect::DnsRedirectError;
use landscape_common::dns::rule::DnsRuleError;
use landscape_common::dns::upstream::DnsUpstreamError;
use landscape_common::error::LdApiErrorInfo;
use landscape_common::flow::ip_mark::DstIpRuleError;
use landscape_common::flow::FlowRuleError;
use landscape_common::lan_service::lan_dhcpv4::DhcpError;
use landscape_common::lan_service::lan_ipv6::LanIPv6Error;
use landscape_common::service::ServiceConfigError;
use landscape_common::sys_service::gateway::GatewayError;
use landscape_common::sys_service::lan_hostname::LanHostnameError;
use landscape_common::wan_service::firewall::FirewallError;
use landscape_common::wan_service::nat::error::NatServiceError;

use crate::api::LandscapeApiResp;
use crate::auth::error::AuthError;
use crate::docker::error::DockerError;
use landscape_common::database::error::DbError;

#[derive(thiserror::Error, Debug)]
pub enum LandscapeApiError {
    // Domain errors — each carries its own error_id and HTTP status
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    DnsRule(#[from] DnsRuleError),
    #[error(transparent)]
    DnsCheck(#[from] DnsServiceError),
    #[error(transparent)]
    DnsUpstream(#[from] DnsUpstreamError),
    #[error(transparent)]
    DnsRedirect(#[from] DnsRedirectError),
    #[error(transparent)]
    DnsProviderProfile(#[from] DnsProviderProfileError),
    #[error(transparent)]
    Ddns(#[from] DdnsError),
    #[error(transparent)]
    FlowRule(#[from] FlowRuleError),
    #[error(transparent)]
    Firewall(#[from] FirewallError),
    #[error(transparent)]
    Dhcp(#[from] DhcpError),
    #[error(transparent)]
    LanIPv6(#[from] LanIPv6Error),
    #[error(transparent)]
    Geo(#[from] GeoError),
    #[error(transparent)]
    StaticNat(#[from] StaticNatError),
    #[error(transparent)]
    NatService(#[from] NatServiceError),
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
    #[error(transparent)]
    Gateway(#[from] GatewayError),
    #[error(transparent)]
    LanHostname(#[from] LanHostnameError),
    #[error(transparent)]
    InitConfig(#[from] InitConfigError),
    #[error("gateway is not supported on this target architecture")]
    GatewayUnsupportedTarget,
    #[error(transparent)]
    Database(#[from] DbError),

    // Generic errors
    #[error("Invalid JSON: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Invalid request body: {0}")]
    JsonRejection(JsonRejection),
}

impl LandscapeApiError {
    pub fn error_id(&self) -> &str {
        match self {
            Self::Cert(e) => e.error_id(),
            Self::DnsRule(e) => e.error_id(),
            Self::DnsCheck(e) => e.error_id(),
            Self::DnsUpstream(e) => e.error_id(),
            Self::DnsRedirect(e) => e.error_id(),
            Self::DnsProviderProfile(e) => e.error_id(),
            Self::Ddns(e) => e.error_id(),
            Self::FlowRule(e) => e.error_id(),
            Self::Firewall(e) => e.error_id(),
            Self::Dhcp(e) => e.error_id(),
            Self::LanIPv6(e) => e.error_id(),
            Self::Geo(e) => e.error_id(),
            Self::StaticNat(e) => e.error_id(),
            Self::NatService(e) => e.error_id(),
            Self::DstIpRule(e) => e.error_id(),
            Self::EnrolledDevice(e) => e.error_id(),
            Self::ServiceConfig(e) => e.error_id(),
            Self::Auth(e) => e.error_id(),
            Self::Docker(e) => e.error_id(),
            Self::Gateway(e) => e.error_id(),
            Self::LanHostname(e) => e.error_id(),
            Self::InitConfig(e) => e.error_id(),
            Self::Database(e) => e.error_id(),
            Self::GatewayUnsupportedTarget => "gateway.unsupported_target",
            Self::JsonError(_) => "request.invalid_json",
            Self::JsonRejection(_) => "request.invalid_body",
        }
    }

    pub fn http_status(&self) -> StatusCode {
        match self {
            Self::Cert(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DnsRule(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DnsCheck(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DnsUpstream(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DnsRedirect(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DnsProviderProfile(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Ddns(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::FlowRule(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Firewall(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Dhcp(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::LanIPv6(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Geo(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::StaticNat(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::NatService(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::DstIpRule(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::EnrolledDevice(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::ServiceConfig(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Auth(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Docker(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Gateway(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::LanHostname(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::InitConfig(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::Database(e) => StatusCode::from_u16(e.http_status_code()).unwrap(),
            Self::GatewayUnsupportedTarget => StatusCode::NOT_IMPLEMENTED,
            Self::JsonError(_) => StatusCode::BAD_REQUEST,
            Self::JsonRejection(r) => r.status(),
        }
    }

    pub fn error_args(&self) -> serde_json::Value {
        match self {
            Self::Cert(e) => e.error_args(),
            Self::DnsRule(e) => e.error_args(),
            Self::DnsCheck(e) => e.error_args(),
            Self::DnsUpstream(e) => e.error_args(),
            Self::DnsRedirect(e) => e.error_args(),
            Self::DnsProviderProfile(e) => e.error_args(),
            Self::Ddns(e) => e.error_args(),
            Self::FlowRule(e) => e.error_args(),
            Self::Firewall(e) => e.error_args(),
            Self::Dhcp(e) => e.error_args(),
            Self::LanIPv6(e) => e.error_args(),
            Self::Geo(e) => e.error_args(),
            Self::StaticNat(e) => e.error_args(),
            Self::NatService(e) => e.error_args(),
            Self::DstIpRule(e) => e.error_args(),
            Self::EnrolledDevice(e) => e.error_args(),
            Self::ServiceConfig(e) => e.error_args(),
            Self::Auth(e) => e.error_args(),
            Self::Docker(e) => e.error_args(),
            Self::Gateway(e) => e.error_args(),
            Self::LanHostname(e) => e.error_args(),
            Self::InitConfig(e) => e.error_args(),
            Self::Database(e) => e.error_args(),
            Self::GatewayUnsupportedTarget | Self::JsonError(_) | Self::JsonRejection(_) => {
                serde_json::json!({})
            }
        }
    }

    /// Public-safe message: database errors only get a generic hint, full details go to logs.
    /// Domain errors forward to their own `to_public_message` so transparently-wrapped
    /// `DbError`s keep their redaction (e.g. nested `DbError::Database`).
    pub fn to_public_message(&self) -> String {
        match self {
            Self::Cert(e) => e.to_public_message(),
            Self::DnsRule(e) => e.to_public_message(),
            Self::DnsCheck(e) => e.to_public_message(),
            Self::DnsUpstream(e) => e.to_public_message(),
            Self::DnsRedirect(e) => e.to_public_message(),
            Self::DnsProviderProfile(e) => e.to_public_message(),
            Self::Ddns(e) => e.to_public_message(),
            Self::FlowRule(e) => e.to_public_message(),
            Self::Firewall(e) => e.to_public_message(),
            Self::Dhcp(e) => e.to_public_message(),
            Self::LanIPv6(e) => e.to_public_message(),
            Self::Geo(e) => e.to_public_message(),
            Self::StaticNat(e) => e.to_public_message(),
            Self::NatService(e) => e.to_public_message(),
            Self::DstIpRule(e) => e.to_public_message(),
            Self::EnrolledDevice(e) => e.to_public_message(),
            Self::ServiceConfig(e) => e.to_public_message(),
            Self::Auth(e) => e.to_public_message(),
            Self::Docker(e) => e.to_public_message(),
            Self::Gateway(e) => e.to_public_message(),
            Self::LanHostname(e) => e.to_public_message(),
            Self::InitConfig(e) => e.to_public_message(),
            Self::Database(e) => e.to_public_message(),
            Self::GatewayUnsupportedTarget | Self::JsonError(_) | Self::JsonRejection(_) => {
                self.to_string()
            }
        }
    }
}

impl IntoResponse for LandscapeApiError {
    fn into_response(self) -> axum::response::Response {
        let status = self.http_status();
        let args = self.error_args();
        let resp = CommonLandscapeApiResp::<()>::error_with_args(
            self.error_id(),
            self.to_public_message(),
            args,
        );
        (status, Json(resp)).into_response()
    }
}

pub type LandscapeApiResult<T> = Result<LandscapeApiResp<T>, LandscapeApiError>;

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::config_service::static_nat::error::StaticNatError;
    use landscape_common::database::error::DbError;
    use landscape_common::ddns::DdnsError;
    use landscape_common::dns::provider_profile::DnsProviderProfileError;
    use landscape_common::flow::FlowRuleError;
    use landscape_common::lan_service::lan_ipv6::LanIPv6Error;
    use sea_orm::DbErr;

    #[test]
    fn direct_db_error_conflict_maps_to_409_conflict() {
        let e = LandscapeApiError::Database(DbError::Conflict);
        assert_eq!(e.error_id(), "config.conflict");
        assert_eq!(e.http_status(), StatusCode::CONFLICT);
        assert_eq!(
            e.to_public_message(),
            "Configuration has been modified by others. Please refresh and try again."
        );
    }

    #[test]
    fn nested_db_error_conflict_delegates_id_status_and_message() {
        for e in [
            LandscapeApiError::Ddns(DdnsError::Internal(DbError::Conflict)),
            LandscapeApiError::FlowRule(FlowRuleError::Internal(DbError::Conflict)),
            LandscapeApiError::StaticNat(StaticNatError::Internal(DbError::Conflict)),
            LandscapeApiError::LanIPv6(LanIPv6Error::Internal(DbError::Conflict)),
            LandscapeApiError::DnsProviderProfile(DnsProviderProfileError::Internal(
                DbError::Conflict,
            )),
        ] {
            assert_eq!(e.error_id(), "config.conflict");
            assert_eq!(e.http_status(), StatusCode::CONFLICT);
            assert_eq!(
                e.to_public_message(),
                "Configuration has been modified by others. Please refresh and try again."
            );
        }
    }

    #[test]
    fn nested_db_error_database_is_redacted() {
        let db_err = DbError::Database(DbErr::Custom("secret constraint detail".to_string()));
        let e = LandscapeApiError::Ddns(DdnsError::Internal(db_err));
        assert_eq!(e.error_id(), "database.error");
        assert_eq!(e.http_status(), StatusCode::INTERNAL_SERVER_ERROR);
        let msg = e.to_public_message();
        assert!(!msg.contains("secret"));
        assert_eq!(msg, "Database operation failed, please try again later");
    }

    #[test]
    fn nested_db_error_conflict_response_is_409() {
        let e = LandscapeApiError::Ddns(DdnsError::Internal(DbError::Conflict));
        let resp = e.into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
