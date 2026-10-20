use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
    sync::Arc,
    time::Duration,
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
use tokio::sync::{Notify, watch};
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type DeviceIpv6Cache = HashMap<Uuid, HashSet<Ipv6Addr>>;

#[derive(Clone)]
pub struct StaticNat6MappingService {
    store: StaticNatMappingV6Repository,
    wan_iid: Arc<u64>,
    directory: Arc<LanDeviceDirectory>,
    dataplane: Arc<dyn NatDataplane>,
    refresh_notify: Arc<Notify>,
    cancel: CancellationToken,
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
            dataplane,
            refresh_notify: Arc::new(Notify::new()),
            cancel: CancellationToken::new(),
        };

        let is_empty = service.store.list().await.is_ok_and(|l| l.is_empty());
        if is_empty {
            service.init_default_rules().await;
        }

        let directory_watch = service.directory.subscribe_watch();
        service.refresh_once().await;
        service.spawn_refresh_worker(directory_watch);

        service
    }

    fn spawn_refresh_worker(&self, mut directory_watch: watch::Receiver<()>) {
        let this = self.clone();
        spawn_task(task_label::task::NAT_STATIC_V6_OBSERVER, async move {
            let cancel = this.cancel.clone();
            if cancel.is_cancelled() {
                return;
            }

            let mut ticker = interval(Duration::from_secs(60));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            ticker.tick().await;

            let mut directory_alive = true;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    changed = directory_watch.changed(), if directory_alive => {
                        if changed.is_err() {
                            directory_alive = false;
                            continue;
                        }
                    }
                    _ = this.refresh_notify.notified() => {}
                    _ = ticker.tick() => {}
                }

                this.refresh_once().await;
            }

            tracing::info!("static NAT v6 refresh worker stopped");
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

    pub fn request_refresh(&self) {
        self.refresh_notify.notify_one();
    }

    pub fn stop(&self) {
        self.cancel.cancel();
    }

    async fn refresh_once(&self) {
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
        self.request_refresh();
    }

    async fn notify_deleted(&self, _old: Self::Config) {
        self.request_refresh();
    }
}

fn is_usable_dynamic_ipv6(ip: &Ipv6Addr) -> bool {
    !(ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_unicast_link_local())
}

fn default_static_mapping_v6_rules() -> Vec<StaticNatMappingV6Config> {
    vec![StaticNatMappingV6Config {
        name: None,
        wan_link_id: None,
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
