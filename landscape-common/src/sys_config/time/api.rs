use serde::{Deserialize, Serialize};

use super::config::LandscapeTimeConfig;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetTimeConfigResponse {
    pub time: LandscapeTimeConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateTimeConfigRequest {
    pub new_time: LandscapeTimeConfig,
    pub expected_hash: String,
}
