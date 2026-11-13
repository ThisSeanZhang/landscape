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

    pub fn update_from_file_config(&mut self, config: &LandscapeDnsConfig) {
        if let Some(v) = config.cache_capacity {
            self.cache_capacity = v;
        }
        if let Some(v) = config.cache_ttl {
            self.cache_ttl = v;
        }
        if let Some(v) = config.negative_cache_ttl {
            self.negative_cache_ttl = v;
        }
        if let Some(v) = config.doh_listen_port {
            self.doh_listen_port = v;
        }
        if let Some(v) = &config.doh_http_endpoint {
            self.doh_http_endpoint = v.clone();
        }
        if let Some(v) = config.tcp_enabled {
            self.tcp_enabled = v;
        }
    }
}
