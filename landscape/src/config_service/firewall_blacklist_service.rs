use landscape_common::{
    event::dns::DstIpEvent,
    firewall::blacklist::{FirewallBlacklistConfig, FirewallBlacklistSource},
    ip_mark::IpConfig,
    service::controller::ConfigController,
};
use landscape_database::{
    firewall_blacklist::repository::FirewallBlacklistRepository,
    provider::LandscapeDBServiceProvider,
};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::geo::ip_service::GeoIpService;

#[derive(Clone)]
pub struct FirewallBlacklistService {
    store: FirewallBlacklistRepository,
    geo_ip_service: GeoIpService,
}

impl FirewallBlacklistService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        geo_ip_service: GeoIpService,
        mut receiver: broadcast::Receiver<DstIpEvent>,
    ) -> Self {
        let store = store.firewall_blacklist_store();
        let service = Self { store, geo_ip_service };

        // Initial full sync
        let configs = service.list().await;
        resolve_and_sync_blacklist(&service.geo_ip_service, configs, vec![]).await;

        // Listen for GeoIP update events
        let service_clone = service.clone();
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv().await {
                match event {
                    DstIpEvent::GeoIpUpdated => {
                        tracing::info!("refresh firewall blacklist due to GeoIP update");
                        let configs = service_clone.list().await;
                        resolve_and_sync_blacklist(&service_clone.geo_ip_service, configs, vec![])
                            .await;
                    }
                }
            }
        });

        service
    }
}

#[async_trait::async_trait]
impl ConfigController for FirewallBlacklistService {
    type Id = Uuid;
    type Config = FirewallBlacklistConfig;
    type DatabseAction = FirewallBlacklistRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }

    async fn after_update_config(
        &self,
        new_configs: Vec<Self::Config>,
        old_configs: Vec<Self::Config>,
    ) {
        resolve_and_sync_blacklist(&self.geo_ip_service, new_configs, old_configs).await;
    }
}

pub async fn resolve_and_sync_blacklist(
    geo_ip_service: &GeoIpService,
    new_configs: Vec<FirewallBlacklistConfig>,
    old_configs: Vec<FirewallBlacklistConfig>,
) {
    let new_ips = resolve_configs(geo_ip_service, &new_configs).await;
    let old_ips = resolve_configs(geo_ip_service, &old_configs).await;

    tracing::info!("sync firewall blacklist: new_ips={}, old_ips={}", new_ips.len(), old_ips.len());

    landscape_ebpf::map_setting::sync_firewall_blacklist(new_ips, old_ips);
}

async fn resolve_configs(
    geo_ip_service: &GeoIpService,
    configs: &[FirewallBlacklistConfig],
) -> Vec<IpConfig> {
    let mut result = vec![];

    for config in configs.iter().filter(|c| c.enable) {
        for source in &config.source {
            match source {
                FirewallBlacklistSource::Config(ip_config) => {
                    result.push(ip_config.clone());
                }
                FirewallBlacklistSource::GeoKey(geo_key) => {
                    let ips = geo_ip_service.resolve_geo_key_to_ips(geo_key).await;
                    result.extend(ips);
                }
            }
        }
    }

    result
}
