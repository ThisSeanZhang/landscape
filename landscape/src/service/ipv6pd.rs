use landscape_common::{
    service::{service_manager::ServiceHandler, DefaultServiceStatus, DefaultWatchServiceStatus},
    store::storev2::LandScapeStore,
    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use serde::{Deserialize, Serialize};

use crate::macaddr::MacAddr;

#[derive(Clone)]
pub struct IPV6PDService;

impl ServiceHandler for IPV6PDService {
    type Status = DefaultServiceStatus;
    type Config = IPV6PDServiceConfig;

    async fn initialize(config: IPV6PDServiceConfig) -> DefaultWatchServiceStatus {
        let service_status = DefaultWatchServiceStatus::new();
        // service_status.just_change_status(ServiceStatus::Staring);
        if config.enable {
            let status_clone = service_status.clone();
            tokio::spawn(async move {
                crate::dhcp_client::v6::dhcp_v6_pd_client(
                    config.iface_name,
                    config.config.mac,
                    LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
                    status_clone,
                )
                .await;
            });
        }

        service_status
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPV6PDServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub config: IPV6PDConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IPV6PDConfig {
    mac: MacAddr,
}

impl LandScapeStore for IPV6PDServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}
