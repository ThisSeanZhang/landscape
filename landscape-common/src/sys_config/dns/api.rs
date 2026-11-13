use serde::{Deserialize, Serialize};

use super::config::LandscapeDnsConfig;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetDnsConfigResponse {
    pub dns: LandscapeDnsConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateDnsConfigRequest {
    pub new_dns: LandscapeDnsConfig,
    pub expected_hash: String,
}
