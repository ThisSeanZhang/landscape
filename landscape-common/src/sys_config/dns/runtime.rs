use serde::{Deserialize, Serialize};

use super::config::{LandscapeDnsCacheConfig, LandscapeDohConfig};
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

impl RuntimeConfigSource for LandscapeDnsCacheConfig {
    type Runtime = CacheRuntimeConfig;
    type Error = DnsServiceError;

    fn validate(&self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn build_runtime(&self) -> CacheRuntimeConfig {
        CacheRuntimeConfig {
            cache_capacity: self.capacity.unwrap_or(crate::DEFAULT_DNS_CACHE_CAPACITY),
            cache_ttl: self.ttl.unwrap_or(crate::DEFAULT_DNS_CACHE_TTL),
            negative_cache_ttl: self.negative_ttl.unwrap_or(crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL),
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

impl RuntimeConfigSource for LandscapeDohConfig {
    type Runtime = DohRuntimeConfig;
    type Error = DnsServiceError;

    fn validate(&self) -> Result<(), Self::Error> {
        if let Some(port) = self.listen_port {
            checked_doh_port(port)?;
        }
        Ok(())
    }

    fn build_runtime(&self) -> DohRuntimeConfig {
        DohRuntimeConfig {
            listen_port: repair_on_error(
                "dns.doh",
                "listen_port",
                checked_doh_port(self.listen_port.unwrap_or(crate::DEFAULT_DNS_DOH_LISTEN_PORT)),
                crate::DEFAULT_DNS_DOH_LISTEN_PORT,
                "using default port",
            ),
            http_endpoint: self.http_endpoint.clone().unwrap_or_else(|| "/dns-query".into()),
        }
    }
}
