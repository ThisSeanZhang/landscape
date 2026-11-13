use serde::{Deserialize, Serialize};

use super::config::LandscapeMetricConfig;

#[derive(Serialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GetMetricConfigResponse {
    pub metric: LandscapeMetricConfig,
    pub hash: String,
}

#[derive(Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateMetricConfigRequest {
    pub new_metric: LandscapeMetricConfig,
    pub expected_hash: String,
}
