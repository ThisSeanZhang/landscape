use serde::{Deserialize, Serialize};

use super::LandscapeLanHostnameConfig;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetLanHostnameConfigResponse {
    pub lan_hostname: LandscapeLanHostnameConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateLanHostnameConfigRequest {
    pub new_lan_hostname: LandscapeLanHostnameConfig,
    pub expected_hash: String,
}
