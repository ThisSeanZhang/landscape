use serde::{Deserialize, Serialize};

use super::config::LandscapeGatewayConfig;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetGatewayConfigResponse {
    pub gateway: LandscapeGatewayConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateGatewayConfigRequest {
    pub new_gateway: LandscapeGatewayConfig,
    pub expected_hash: String,
}
