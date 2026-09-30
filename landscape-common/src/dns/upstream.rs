use serde::{Deserialize, Serialize};

pub use super::error::DnsUpstreamError;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
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
