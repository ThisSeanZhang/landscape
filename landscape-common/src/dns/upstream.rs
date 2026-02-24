use landscape_macro::LdApiError;
use serde::{Deserialize, Serialize};

use crate::config::ConfigId;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum DnsUpstreamError {
    #[error("DNS upstream config '{0}' not found")]
    #[api_error(id = "dns_upstream.not_found", status = 404)]
    NotFound(ConfigId),
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
#[serde(tag = "t")]
pub enum DnsUpstreamMode {
    #[default]
    Plaintext, // 传统 DNS（UDP/TCP，无加密）
    Tls {
        domain: String,
    }, // DNS over TLS (DoT)
    Https {
        domain: String,
        #[serde(default)]
        #[cfg_attr(feature = "openapi", schema(required = true, nullable = true))]
        http_endpoint: Option<String>,
    }, // DNS over HTTPS (DoH)
    Quic {
        domain: String,
    }, // DNS over Quic (DoQ)
}
