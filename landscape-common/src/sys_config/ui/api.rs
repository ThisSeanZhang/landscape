use serde::{Deserialize, Serialize};

use super::config::LandscapeUiConfig;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetUiConfigResponse {
    pub ui: LandscapeUiConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateUiConfigRequest {
    pub new_ui: LandscapeUiConfig,
    pub expected_hash: String,
}
