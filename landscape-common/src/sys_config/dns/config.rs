use serde::{Deserialize, Serialize};

use crate::service::ServiceConfigError;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeDnsConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cache_capacity: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub cache_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub negative_cache_ttl: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub doh_listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub doh_http_endpoint: Option<String>,
    /// Serve plain DNS over TCP on the DNS/UDP port. Defaults to on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub tcp_enabled: Option<bool>,
}

impl LandscapeDnsConfig {
    /// Reject configurations the listener cannot honour. DNS/UDP and DNS/TCP
    /// own port 53; DoH must use a different port, otherwise one reuseport
    /// group would need two dispatcher programs.
    pub fn validate(&self) -> Result<(), ServiceConfigError> {
        if self.doh_listen_port == Some(crate::DNS_LISTEN_PORT) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "doh_listen_port must not be {} (reserved for DNS/UDP and DNS/TCP), got {}",
                    crate::DNS_LISTEN_PORT,
                    crate::DNS_LISTEN_PORT
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
    fn dns_config_rejects_doh_on_port_53() {
        let config = LandscapeDnsConfig {
            doh_listen_port: Some(crate::DNS_LISTEN_PORT),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn dns_config_accepts_other_doh_ports_and_default() {
        assert!(LandscapeDnsConfig::default().validate().is_ok());
        let config = LandscapeDnsConfig {
            doh_listen_port: Some(crate::DEFAULT_DNS_DOH_LISTEN_PORT),
            tcp_enabled: Some(false),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
