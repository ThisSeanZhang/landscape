use serde::{Deserialize, Serialize};

use super::config::LandscapeDnsConfig;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CacheRuntimeConfig {
    pub cache_capacity: u32,
    pub cache_ttl: u32,
    pub negative_cache_ttl: u32,
}

impl Default for CacheRuntimeConfig {
    fn default() -> Self {
        Self {
            cache_capacity: crate::DEFAULT_DNS_CACHE_CAPACITY,
            cache_ttl: crate::DEFAULT_DNS_CACHE_TTL,
            negative_cache_ttl: crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DohRuntimeConfig {
    pub listen_port: u16,
    pub http_endpoint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRuntimeConfig {
    pub cache_capacity: u32,
    pub cache_ttl: u32,
    pub negative_cache_ttl: u32,
    pub doh_listen_port: u16,
    pub doh_http_endpoint: String,
    /// Plain DNS-over-TCP on the DNS/UDP port. Defaults to enabled.
    pub tcp_enabled: bool,
}

impl DnsRuntimeConfig {
    pub fn cache_runtime(&self) -> CacheRuntimeConfig {
        CacheRuntimeConfig {
            cache_capacity: self.cache_capacity,
            cache_ttl: self.cache_ttl,
            negative_cache_ttl: self.negative_cache_ttl,
        }
    }

    /// Whether the plain DNS/TCP listener is enabled.
    pub fn dns_tcp_enabled(&self) -> bool {
        self.tcp_enabled
    }

    pub fn doh_runtime(&self) -> DohRuntimeConfig {
        DohRuntimeConfig {
            listen_port: self.doh_listen_port,
            http_endpoint: self.doh_http_endpoint.clone(),
        }
    }

    /// Build a complete runtime configuration; omitted fields use defaults.
    pub fn from_file_config(config: &LandscapeDnsConfig) -> Self {
        Self {
            cache_capacity: config.cache_capacity.unwrap_or(crate::DEFAULT_DNS_CACHE_CAPACITY),
            cache_ttl: config.cache_ttl.unwrap_or(crate::DEFAULT_DNS_CACHE_TTL),
            negative_cache_ttl: config
                .negative_cache_ttl
                .unwrap_or(crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL),
            doh_listen_port: config.doh_listen_port.unwrap_or(crate::DEFAULT_DNS_DOH_LISTEN_PORT),
            doh_http_endpoint: config
                .doh_http_endpoint
                .clone()
                .unwrap_or_else(|| "/dns-query".to_string()),
            tcp_enabled: config.tcp_enabled.unwrap_or(crate::DEFAULT_DNS_TCP_ENABLE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_fields_restores_defaults_after_file_round_trip() {
        let mut file_config = LandscapeDnsConfig {
            cache_capacity: Some(1234),
            cache_ttl: Some(42),
            negative_cache_ttl: Some(7),
            doh_listen_port: Some(8443),
            doh_http_endpoint: Some("/custom".into()),
            tcp_enabled: Some(false),
        };
        let customized = DnsRuntimeConfig::from_file_config(&file_config);
        file_config = LandscapeDnsConfig::default();
        let updated = DnsRuntimeConfig::from_file_config(&file_config);
        let saved = toml::to_string(&file_config).unwrap();
        let reloaded: LandscapeDnsConfig = toml::from_str(&saved).unwrap();
        let restarted = DnsRuntimeConfig::from_file_config(&reloaded);
        assert_eq!(updated, restarted);
        assert_ne!(customized, updated);
        assert_eq!(updated.doh_listen_port, crate::DEFAULT_DNS_DOH_LISTEN_PORT);
        assert_eq!(updated.tcp_enabled, crate::DEFAULT_DNS_TCP_ENABLE);
    }
}
