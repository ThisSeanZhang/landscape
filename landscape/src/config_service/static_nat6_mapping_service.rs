use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
    sync::Arc,
};

use landscape_common::LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT;
use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::config_service::static_nat::config6::{
    StaticNatMappingV6Config, StaticNatV6PortConfig, StaticNatV6Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::store::{Change, ConfigStore};
use landscape_common::service::controller::ConfigStoreController;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::static_nat_mapping_v6::repository::StaticNatMappingV6Repository;
use tokio::sync::Mutex;
use uuid::Uuid;

type DeviceIpv6Cache = HashMap<Uuid, HashSet<Ipv6Addr>>;

#[derive(Clone)]
pub struct StaticNat6MappingService {
    store: StaticNatMappingV6Repository,
    wan_iid: Arc<u64>,
    directory: Arc<LanDeviceDirectory>,
    refresh_lock: Arc<Mutex<()>>,
    dataplane: Arc<dyn NatDataplane>,
}

impl StaticNat6MappingService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        directory: Arc<LanDeviceDirectory>,
        wan_iid: Arc<u64>,
        dataplane: Arc<dyn NatDataplane>,
    ) -> Self {
        let service = Self {
            store: store_provider.static_nat_mapping_v6_store(),
            wan_iid,
            directory,
            refresh_lock: Arc::new(Mutex::new(())),
            dataplane,
        };

        let is_empty = service.store.list().await.is_ok_and(|l| l.is_empty());
        if is_empty {
            service.init_default_rules().await;
        }

        // Subscribe before the initial refresh: any snapshot swap happening
        // while the refresh reads would otherwise leave the ruleset stale
        // until the next change. The refresh lock serializes the two paths.
        service.spawn_directory_watch_loop();

        service.refresh_runtime_rules().await;

        service
    }

    /// Full-refresh consumer: the directory's coalesced dirty signal is the
    /// natural trigger. The signal fires after the snapshot swap, so the
    /// refresh below always reads a consistent post-change cut.
    fn spawn_directory_watch_loop(&self) {
        let this = self.clone();
        let mut watch_rx = self.directory.subscribe_watch();
        spawn_task(task_label::task::NAT_STATIC_V6_OBSERVER, async move {
            loop {
                if watch_rx.changed().await.is_err() {
                    break;
                }
                this.refresh_runtime_rules().await;
            }
            tracing::info!("static NAT v6 directory watch loop stopped");
        });
    }

    async fn init_default_rules(&self) {
        if let Err(error) = self.store.upsert_many(default_static_mapping_v6_rules()).await {
            tracing::error!("failed to seed default static NAT v6 rules: {error:?}");
        }
    }

    // --- V6 CRUD ---

    pub async fn validate_runtime_target(
        &self,
        config: &StaticNatMappingV6Config,
    ) -> Result<(), StaticNatError> {
        self.store.validate_runtime_target_v6(config).await
    }

    // --- Runtime ---

    pub async fn refresh_runtime_rules(&self) {
        let _refresh_guard = self.refresh_lock.lock().await;
        let device_ipv6_cache: DeviceIpv6Cache = self
            .directory
            .snapshot()
            .ipv6_sets_by_device_id()
            .into_iter()
            .map(|(id, set)| {
                (id, set.into_iter().filter(is_usable_dynamic_ipv6).collect::<HashSet<_>>())
            })
            .filter(|(_, set)| !set.is_empty())
            .collect();
        let configs =
            match self.store.list_runtime_configs_v6(*self.wan_iid, &device_ipv6_cache).await {
                Ok(configs) => configs,
                Err(error) => {
                    tracing::error!("failed to load static NAT v6 runtime configs: {error:?}");
                    return;
                }
            };

        self.dataplane.sync_static_nat6(&configs);
    }
}

#[async_trait::async_trait]
impl ConfigStoreController for StaticNat6MappingService {
    type Id = Uuid;
    type Config = StaticNatMappingV6Config;
    type Store = StaticNatMappingV6Repository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }

    async fn notify_changed(&self, _changes: Vec<Change<Self::Config>>) {
        self.refresh_runtime_rules().await;
    }

    async fn notify_deleted(&self, _old: Self::Config) {
        self.refresh_runtime_rules().await;
    }
}

fn is_usable_dynamic_ipv6(ip: &Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_unicast_link_local())
}

fn default_static_mapping_v6_rules() -> Vec<StaticNatMappingV6Config> {
    vec![StaticNatMappingV6Config {
        name: None,
        wan_iface_name: None,
        lan_target: Some(StaticNatV6Target::Local),
        l4_protocols: vec![17],
        id: Uuid::new_v4(),
        enable: true,
        remark: "Default DHCPv6 Client Port".to_string(),
        update_at: get_f64_timestamp(),
        port_config: StaticNatV6PortConfig::Ports {
            ports: vec![LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT],
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dhcpv6_rule_targets_local_wan_iid() {
        let rules = default_static_mapping_v6_rules();
        assert_eq!(rules.len(), 1);
        assert!(matches!(rules[0].lan_target, Some(StaticNatV6Target::Local)));
    }
}
