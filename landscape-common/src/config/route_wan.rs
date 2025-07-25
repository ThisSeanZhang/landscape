use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::utils::time::get_f64_timestamp;
use crate::{database::repository::LandscapeDBStore, store::storev2::LandscapeStore};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[ts(export, export_to = "common/route.d.ts")]
pub struct RouteWanServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default = "get_f64_timestamp")]
    pub update_at: f64,
}

impl LandscapeStore for RouteWanServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl LandscapeDBStore<String> for RouteWanServiceConfig {
    fn get_id(&self) -> String {
        self.iface_name.clone()
    }
}
