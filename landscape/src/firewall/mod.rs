use landscape_common::{
    service::{service_manager::ServiceHandler, DefaultServiceStatus, DefaultWatchServiceStatus},
    store::storev2::LandScapeStore,
};
use serde::{Deserialize, Serialize};

pub mod rules;

#[derive(Clone)]
pub struct FirewallService;

impl ServiceHandler for FirewallService {
    type Status = DefaultServiceStatus;

    type Config = FirewallServiceConfig;

    async fn initialize(_: FirewallServiceConfig) -> DefaultWatchServiceStatus {
        // let service_status = DefaultWatchServiceStatus::new();
        todo!()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallServiceConfig {
    pub iface_name: String,
    pub enable: bool,
}

impl LandScapeStore for FirewallServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}
