use std::net::Ipv4Addr;
use std::sync::Arc;

use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT;
use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::config_service::static_nat::config::StaticMapPair;
use landscape_common::config_service::static_nat::config4::{
    StaticNatMappingV4Config, StaticNatV4Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::error::DbError;
use landscape_common::database::store::{Change, ConfigStore};
use landscape_common::event::hub::EnrolledDeviceEventReader;
use landscape_common::service::controller::ConfigStoreController;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::static_nat_mapping_v4::repository::StaticNatMappingV4Repository;
use uuid::Uuid;

#[derive(Clone)]
pub struct StaticNat4MappingService {
    store: StaticNatMappingV4Repository,
    dataplane: Arc<dyn NatDataplane>,
}

impl StaticNat4MappingService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        device_reader: EnrolledDeviceEventReader,
        dataplane: Arc<dyn NatDataplane>,
    ) -> Self {
        let service = Self {
            store: store_provider.static_nat_mapping_v4_store(),
            dataplane,
        };

        let is_empty = service.store.list().await.is_ok_and(|l| l.is_empty());
        if is_empty {
            service.init_default_rules().await;
        }

        service.refresh_runtime_rules().await;

        let this = service.clone();
        spawn_task(task_label::task::NAT_STATIC_V4_OBSERVER, async move {
            let mut rx = device_reader;
            while rx.recv().await.is_ok() {
                this.refresh_runtime_rules().await;
            }
        });

        service
    }

    async fn init_default_rules(&self) {
        if let Err(error) = self.store.upsert_many(default_static_mapping_v4_rules()).await {
            tracing::error!("failed to seed default static NAT v4 rules: {error:?}");
        }
    }

    // --- V4 CRUD ---

    pub async fn validate_runtime_target(
        &self,
        config: &StaticNatMappingV4Config,
    ) -> Result<(), StaticNatError> {
        self.store.validate_runtime_target_v4(config).await
    }

    pub async fn check_port_conflict(
        &self,
        wan_port: u16,
        protocols: &[u8],
    ) -> Result<Option<StaticNatError>, DbError> {
        for (iface_name, nat_config) in self.store.enabled_link_nats().await? {
            for proto in protocols {
                let range = match *proto {
                    6 => &nat_config.tcp_range,
                    17 => &nat_config.udp_range,
                    _ => continue,
                };
                if wan_port >= range.start && wan_port <= range.end {
                    return Ok(Some(StaticNatError::PortConflict {
                        port: wan_port,
                        iface_name,
                        protocol: *proto,
                        start: range.start,
                        end: range.end,
                    }));
                }
            }
        }
        Ok(None)
    }

    // --- Runtime ---

    async fn refresh_runtime_rules(&self) {
        let configs = match self.store.list_runtime_configs_v4().await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!("failed to load static NAT v4 runtime configs: {error:?}");
                Vec::new()
            }
        };

        self.dataplane.sync_static_nat4(&configs);
    }
}

#[async_trait::async_trait]
impl ConfigStoreController for StaticNat4MappingService {
    type Id = Uuid;
    type Config = StaticNatMappingV4Config;
    type Store = StaticNatMappingV4Repository;

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

fn default_static_mapping_v4_rules() -> Vec<StaticNatMappingV4Config> {
    let mut result = Vec::with_capacity(4);
    // DHCPv4 Client
    result.push(StaticNatMappingV4Config {
        name: None,
        wan_link_id: None,
        wan_iface_name: None,
        lan_target: Some(StaticNatV4Target::address(Ipv4Addr::UNSPECIFIED)),
        l4_protocols: vec![17],
        id: Uuid::new_v4(),
        enable: true,
        remark: "Default DHCPv4 Client Port".to_string(),
        update_at: get_f64_timestamp(),
        mapping_pair_ports: vec![StaticMapPair {
            wan_port: LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
            lan_port: LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT,
        }],
    });
    #[cfg(debug_assertions)]
    {
        result.push(StaticNatMappingV4Config {
            name: None,
            wan_link_id: None,
            wan_iface_name: None,
            lan_target: Some(StaticNatV4Target::address(Ipv4Addr::UNSPECIFIED)),
            l4_protocols: vec![6, 17],
            id: Uuid::new_v4(),
            enable: true,
            remark: "For Test".to_string(),
            update_at: get_f64_timestamp(),
            mapping_pair_ports: vec![StaticMapPair { wan_port: 8080, lan_port: 8081 }],
        });
        result.push(StaticNatMappingV4Config {
            name: None,
            wan_link_id: None,
            wan_iface_name: None,
            lan_target: Some(StaticNatV4Target::address(Ipv4Addr::UNSPECIFIED)),
            l4_protocols: vec![6],
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            update_at: get_f64_timestamp(),
            mapping_pair_ports: vec![StaticMapPair { wan_port: 5173, lan_port: 5173 }],
        });
        result.push(StaticNatMappingV4Config {
            name: None,
            wan_link_id: None,
            wan_iface_name: None,
            lan_target: Some(StaticNatV4Target::address(Ipv4Addr::UNSPECIFIED)),
            l4_protocols: vec![6],
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            update_at: get_f64_timestamp(),
            mapping_pair_ports: vec![StaticMapPair { wan_port: 22, lan_port: 22 }],
        });
    }
    result
}
