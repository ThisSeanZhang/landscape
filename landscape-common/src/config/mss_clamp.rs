use serde::{Deserialize, Serialize};

use crate::database::repository::LandscapeDBStore;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MSSClampServiceConfig {
    pub iface_name: String,
    pub enable: bool,

    #[serde(default = "default_clamp_size")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub clamp_size: u16,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

impl LandscapeStore for MSSClampServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for MSSClampServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}

/// PPPoE: 1500 - 8 = 1492
const fn default_clamp_size() -> u16 {
    1492
}
