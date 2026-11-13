use serde::{Deserialize, Serialize};

use super::config::LandscapeUIConfig;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetUIConfigResponse {
    pub ui: LandscapeUIConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateUIConfigRequest {
    pub new_ui: LandscapeUIConfig,
    pub expected_hash: String,
}
