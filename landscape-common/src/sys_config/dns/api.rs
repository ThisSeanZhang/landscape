use super::config::{LandscapeDnsCacheConfig, LandscapeDohConfig};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDnsCacheConfigResponse {
    pub cache: LandscapeDnsCacheConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDnsCacheConfigRequest {
    pub new_cache: LandscapeDnsCacheConfig,
    pub expected_hash: String,
}

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDohConfigResponse {
    pub doh: LandscapeDohConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDohConfigRequest {
    pub new_doh: LandscapeDohConfig,
    pub expected_hash: String,
}
