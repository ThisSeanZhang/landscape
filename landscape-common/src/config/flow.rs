use serde::{Deserialize, Serialize};

use crate::utils::time::get_f64_timestamp;
use crate::{database::repository::LandscapeDBStore, store::storev2::LandscapeStore};

/// 可移除
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct FlowWanServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

impl LandscapeStore for FlowWanServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for FlowWanServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}
