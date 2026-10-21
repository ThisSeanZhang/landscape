use std::sync::Arc;

use landscape_common::{
    concurrency::{spawn_task, task_label},
    database::store::Change,
    event::dns::DstIpEvent,
    flow::ip_mark::IpConfig,
    service::controller::ConfigStoreController,
    wan_service::firewall::blacklist::{FirewallBlacklistConfig, FirewallBlacklistSource},
    wan_service::firewall::dataplane::FirewallDataplane,
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
    dataplane: Arc<dyn FirewallDataplane>,
}

impl FirewallBlacklistService {
    pub async fn new(
        store: LandscapeDBServiceProvider,
        geo_ip_service: GeoIpService,
        mut receiver: broadcast::Receiver<DstIpEvent>,
        dataplane: Arc<dyn FirewallDataplane>,
    ) -> Self {
        let store = store.firewall_blacklist_store();
        let service = Self { store, geo_ip_service, dataplane };

        // Initial full sync
        let configs = service.list().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "reading firewall blacklist configs for initial sync failed");
            Vec::new()
        });
        resolve_and_sync_blacklist(
            &service.geo_ip_service,
            configs,
            vec![],
            service.dataplane.as_ref(),
        )
        .await;

        // Listen for GeoIP update events
        let service_clone = service.clone();
        spawn_task(task_label::task::FIREWALL_BLACKLIST_OBSERVER, async move {
            while let Ok(event) = receiver.recv().await {
                match event {
                    DstIpEvent::GeoIpUpdated { changed_keys } => {
                        tracing::info!(
                            "refresh firewall blacklist for {} changed geo key(s)",
                            changed_keys.len()
                        );
                        let configs = service_clone.list().await.unwrap_or_default();
                        let affected = affected_blacklist_configs(configs, &changed_keys);
                        if affected.is_empty() {
                            continue;
                        }
                        resolve_and_sync_blacklist(
                            &service_clone.geo_ip_service,
                            affected,
                            vec![],
                            service_clone.dataplane.as_ref(),
                        )
                        .await;
                    }
                }
            }
        });

        service
    }
}

#[async_trait::async_trait]
impl ConfigStoreController for FirewallBlacklistService {
    type Id = Uuid;
    type Config = FirewallBlacklistConfig;
    type Store = FirewallBlacklistRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, changes: Vec<Change<Self::Config>>) {
        let new_configs: Vec<_> = changes.iter().map(|c| c.new.clone()).collect();
        let old_configs: Vec<_> = changes.iter().filter_map(|c| c.old.clone()).collect();
        resolve_and_sync_blacklist(
            &self.geo_ip_service,
            new_configs,
            old_configs,
            self.dataplane.as_ref(),
        )
        .await;
    }

    async fn notify_deleted(&self, old: Self::Config) {
        resolve_and_sync_blacklist(
            &self.geo_ip_service,
            vec![],
            vec![old],
            self.dataplane.as_ref(),
        )
        .await;
    }
}

fn affected_blacklist_configs(
    configs: Vec<FirewallBlacklistConfig>,
    changed_keys: &std::collections::HashSet<
        landscape_common::config_service::geo::GeoFileCacheKey,
    >,
) -> Vec<FirewallBlacklistConfig> {
    configs
        .into_iter()
        .filter(|config| {
            config.enable
                && config.source.iter().any(|source| match source {
                    FirewallBlacklistSource::GeoKey(key) => {
                        changed_keys.iter().any(|changed| key.matches_file_cache_key(changed))
                    }
                    FirewallBlacklistSource::Config(_) => false,
                })
        })
        .collect()
}

pub async fn resolve_and_sync_blacklist(
    geo_ip_service: &GeoIpService,
    new_configs: Vec<FirewallBlacklistConfig>,
    old_configs: Vec<FirewallBlacklistConfig>,
    dataplane: &dyn FirewallDataplane,
) {
    let new_ips = resolve_configs(geo_ip_service, &new_configs).await;
    let old_ips = resolve_configs(geo_ip_service, &old_configs).await;

    tracing::info!("sync firewall blacklist: new_ips={}, old_ips={}", new_ips.len(), old_ips.len());

    dataplane.sync_blacklist(new_ips, old_ips);
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
                    geo_ip_service.extend_geo_key_ips(geo_key, &mut result).await;
                }
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use landscape_common::{
        config_service::geo::{GeoConfigKey, GeoFileCacheKey},
        flow::IpConfig,
    };
    use uuid::Uuid;

    use super::{FirewallBlacklistConfig, FirewallBlacklistSource, affected_blacklist_configs};

    fn geo_key(key: &str) -> GeoConfigKey {
        GeoConfigKey {
            name: "geoip".to_string(),
            key: key.to_string(),
            inverse: false,
            attribute_key: None,
        }
    }

    fn config(enable: bool, source: Vec<FirewallBlacklistSource>) -> FirewallBlacklistConfig {
        FirewallBlacklistConfig {
            id: Uuid::new_v4(),
            name: None,
            enable,
            source,
            remark: String::new(),
            update_at: 0.0,
        }
    }

    #[test]
    fn only_blacklists_referencing_changed_geo_keys_are_selected() {
        let configs = vec![
            config(true, vec![FirewallBlacklistSource::GeoKey(geo_key("CN"))]),
            config(true, vec![FirewallBlacklistSource::GeoKey(geo_key("US"))]),
            config(
                true,
                vec![FirewallBlacklistSource::Config(IpConfig {
                    ip: "192.0.2.1".parse().unwrap(),
                    prefix: 24,
                })],
            ),
            config(false, vec![FirewallBlacklistSource::GeoKey(geo_key("CN"))]),
        ];
        let changed =
            HashSet::from([GeoFileCacheKey { name: "geoip".to_string(), key: "CN".to_string() }]);

        let affected = affected_blacklist_configs(configs, &changed);
        assert_eq!(affected.len(), 1);
        assert!(matches!(
            affected[0].source[0],
            FirewallBlacklistSource::GeoKey(ref key) if key.key == "CN"
        ));
    }
}
