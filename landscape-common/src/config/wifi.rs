use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::database::repository::LandscapeDBStore;
use crate::store::storev2::LandscapeStore;
use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/config.d.ts")]
pub struct WifiServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    /// hostapd config file
    pub config: String,
    #[serde(default = "get_f64_timestamp")]
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub update_at: f64,
}

impl LandscapeStore for WifiServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for WifiServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}
