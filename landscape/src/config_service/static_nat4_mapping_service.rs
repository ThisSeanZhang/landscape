use std::net::Ipv4Addr;

use landscape_common::config_service::static_nat::config::StaticMapPair;
use landscape_common::config_service::static_nat::config4::{
    StaticNatMappingV4Config, StaticNatV4Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::LandscapeStore;
use landscape_common::error::LdError;
use landscape_common::event::hub::EnrolledDeviceEventReader;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT;
use landscape_database::nat::repository::NatServiceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::static_nat_mapping_v4::repository::StaticNatMappingV4Repository;
use uuid::Uuid;

#[derive(Clone)]
pub struct StaticNat4MappingService {
    store: StaticNatMappingV4Repository,
    nat_store: NatServiceRepository,
}

impl StaticNat4MappingService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        device_reader: EnrolledDeviceEventReader,
    ) -> Self {
        let service = Self {
            store: store_provider.static_nat_mapping_v4_store(),
            nat_store: store_provider.nat_service_store(),
        };

        let is_empty = service.store.list().await.is_ok_and(|l| l.is_empty());
        if is_empty {
            service.init_default_rules().await;
        }

        service.refresh_runtime_rules().await;

        let this = service.clone();
        tokio::spawn(async move {
            let mut rx = device_reader;
            while rx.recv().await.is_ok() {
                this.refresh_runtime_rules().await;
            }
        });

        service
    }

    async fn init_default_rules(&self) {
        for config in default_static_mapping_v4_rules() {
            let _ = self.store.set(config).await;
        }
    }

    // --- V4 CRUD ---

    pub async fn list(&self) -> Vec<StaticNatMappingV4Config> {
        self.store.list().await.unwrap_or_default()
    }

    pub async fn find_by_id(&self, id: Uuid) -> Option<StaticNatMappingV4Config> {
        self.store.find_by_id(id).await.ok()?
    }

    pub async fn checked_set(
        &self,
        config: StaticNatMappingV4Config,
    ) -> Result<StaticNatMappingV4Config, LdError> {
        let result = self.store.checked_set(config).await?;
        self.refresh_runtime_rules().await;
        Ok(result)
    }

    pub async fn checked_set_list(
        &self,
        configs: Vec<StaticNatMappingV4Config>,
    ) -> Result<(), LdError> {
        for config in &configs {
            self.store.check_conflict(config).await?;
        }
        for config in configs {
            self.store.checked_set(config).await?;
        }
        self.refresh_runtime_rules().await;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) {
        if self.find_by_id(id).await.is_some() {
            let _ = self.store.delete(id).await;
            self.refresh_runtime_rules().await;
        }
    }

    pub async fn validate_runtime_target(
        &self,
        config: &StaticNatMappingV4Config,
    ) -> Result<(), StaticNatError> {
        self.store.validate_runtime_target_v4(config).await
    }

    pub async fn check_dynamic_range_overlap(
        &self,
        nat_config: &NatConfig,
    ) -> Result<(), StaticNatError> {
        let mappings = self.store.list().await.map_err(StaticNatError::Internal)?;
        for (proto, range) in [(6u8, &nat_config.tcp_range), (17u8, &nat_config.udp_range)] {
            for mapping in &mappings {
                if !mapping.enable || !mapping.l4_protocols.contains(&proto) {
                    continue;
                }
                for pair in &mapping.mapping_pair_ports {
                    if pair.wan_port >= range.start && pair.wan_port <= range.end {
                        return Err(StaticNatError::PortInDynamicRange {
                            mapping_id: mapping.id,
                            port: pair.wan_port,
                            protocol: proto,
                            start: range.start,
                            end: range.end,
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn check_port_conflict(
        &self,
        wan_port: u16,
        protocols: &[u8],
    ) -> Result<Option<StaticNatError>, LdError> {
        let Some(nat_config) = self.nat_store.find_active_nat_config().await? else {
            return Ok(None);
        };
        for proto in protocols {
            let range = match *proto {
                6 => &nat_config.nat_config.tcp_range,
                17 => &nat_config.nat_config.udp_range,
                _ => continue,
            };
            if wan_port >= range.start && wan_port <= range.end {
                return Ok(Some(StaticNatError::PortConflict {
                    port: wan_port,
                    iface_name: nat_config.iface_name.clone(),
                    protocol: *proto,
                    start: range.start,
                    end: range.end,
                }));
            }
        }
        Ok(None)
    }

    pub async fn validate_no_dynamic_port_conflict(
        &self,
        config: &StaticNatMappingV4Config,
    ) -> Result<(), StaticNatError> {
        if !config.enable || config.mapping_pair_ports.is_empty() || config.l4_protocols.is_empty()
        {
            return Ok(());
        }
        let Some(nat_config) = self.nat_store.find_active_nat_config().await? else {
            return Ok(());
        };
        for proto in &config.l4_protocols {
            let range = match *proto {
                6 => &nat_config.nat_config.tcp_range,
                17 => &nat_config.nat_config.udp_range,
                _ => continue,
            };
            for pair in &config.mapping_pair_ports {
                if pair.wan_port >= range.start && pair.wan_port <= range.end {
                    return Err(StaticNatError::PortConflict {
                        port: pair.wan_port,
                        iface_name: nat_config.iface_name.clone(),
                        protocol: *proto,
                        start: range.start,
                        end: range.end,
                    });
                }
            }
        }
        Ok(())
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

        if let Err(error) = landscape_ebpf::map_setting::nat::reconcile_static_nat4_map(&configs) {
            tracing::error!("failed to reconcile static NAT v4 map: {error:?}");
        }
    }
}

fn default_static_mapping_v4_rules() -> Vec<StaticNatMappingV4Config> {
    let mut result = Vec::with_capacity(4);
    // DHCPv4 Client
    result.push(StaticNatMappingV4Config {
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
