use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use crate::config_service::geo::GeoFileCacheKey;

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FlowDnsDependencies {
    pub geo_keys: HashSet<GeoFileCacheKey>,
    pub upstream_ids: HashSet<Uuid>,
    pub dynamic_redirect_sources: HashSet<String>,
}
