use serde::{Deserialize, Serialize};

use super::config::LandscapeDnsConfig;
use crate::dns::error::DnsServiceError;
use crate::sys_config::{RuntimeConfigSource, runtime::repair_on_error};

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
}

// DNS/UDP and DNS/TCP own port 53; DoH must use a different port.
fn checked_doh_port(port: u16) -> Result<u16, DnsServiceError> {
    if port == crate::DNS_LISTEN_PORT {
        Err(DnsServiceError::DohPortConflict { port })
    } else {
        Ok(port)
    }
}

impl RuntimeConfigSource for LandscapeDnsConfig {
    type Runtime = DnsRuntimeConfig;
    type Error = DnsServiceError;

    fn validate(&self) -> Result<(), Self::Error> {
        if let Some(port) = self.doh_listen_port {
            checked_doh_port(port)?;
        }
        Ok(())
    }

    fn build_runtime(&self) -> Self::Runtime {
        DnsRuntimeConfig {
            cache_capacity: self.cache_capacity.unwrap_or(crate::DEFAULT_DNS_CACHE_CAPACITY),
            cache_ttl: self.cache_ttl.unwrap_or(crate::DEFAULT_DNS_CACHE_TTL),
            negative_cache_ttl: self
                .negative_cache_ttl
                .unwrap_or(crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL),
            doh_listen_port: repair_on_error(
                "dns",
                "doh_listen_port",
                checked_doh_port(
                    self.doh_listen_port.unwrap_or(crate::DEFAULT_DNS_DOH_LISTEN_PORT),
                ),
                crate::DEFAULT_DNS_DOH_LISTEN_PORT,
                "using default port",
            ),
            doh_http_endpoint: self
                .doh_http_endpoint
                .clone()
                .unwrap_or_else(|| "/dns-query".to_string()),
            tcp_enabled: self.tcp_enabled.unwrap_or(crate::DEFAULT_DNS_TCP_ENABLE),
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
        let customized = file_config.to_runtime().unwrap();
        file_config = LandscapeDnsConfig::default();
        let updated = file_config.to_runtime().unwrap();
        let saved = toml::to_string(&file_config).unwrap();
        let reloaded: LandscapeDnsConfig = toml::from_str(&saved).unwrap();
        let restarted = reloaded.to_runtime().unwrap();
        assert_eq!(updated, restarted);
        assert_ne!(customized, updated);
        assert_eq!(updated.doh_listen_port, crate::DEFAULT_DNS_DOH_LISTEN_PORT);
        assert_eq!(updated.tcp_enabled, crate::DEFAULT_DNS_TCP_ENABLE);
    }
    #[test]
    fn conversion_rejects_doh_on_dns_port() {
        let config = LandscapeDnsConfig {
            doh_listen_port: Some(crate::DNS_LISTEN_PORT),
            ..Default::default()
        };
        assert!(matches!(
            config.to_runtime(),
            Err(crate::dns::error::DnsServiceError::DohPortConflict { .. })
        ));
    }
    #[test]
    fn startup_repairs_only_the_doh_port_while_updates_reject_it() {
        let config = LandscapeDnsConfig {
            doh_listen_port: Some(crate::DNS_LISTEN_PORT),
            cache_capacity: Some(123),
            cache_ttl: Some(42),
            doh_http_endpoint: Some("/custom".into()),
            tcp_enabled: Some(false),
            ..Default::default()
        };
        assert!(config.to_runtime().is_err());
        let runtime = config.build_runtime();
        assert_eq!(runtime.doh_listen_port, crate::DEFAULT_DNS_DOH_LISTEN_PORT);
        assert_eq!(runtime.cache_capacity, 123);
        assert_eq!(runtime.cache_ttl, 42);
        assert_eq!(runtime.doh_http_endpoint, "/custom");
        assert!(!runtime.tcp_enabled);
        assert_eq!(config.doh_listen_port, Some(crate::DNS_LISTEN_PORT));
    }
}
