use std::net::{Ipv4Addr, Ipv6Addr};

use landscape_common::database::LandscapeStore;
use landscape_common::error::LdError;
use landscape_common::iface::nat::{
    StaticMapPair, StaticNatMappingV4Config, StaticNatMappingV6Config, StaticNatV4Target,
    StaticNatV6PortConfig, StaticNatV6Target,
};
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::{
    LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT, LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
};
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::static_nat_mapping_v4::repository::StaticNatMappingV4Repository;
use landscape_database::static_nat_mapping_v6::repository::StaticNatMappingV6Repository;
use uuid::Uuid;

#[derive(Clone)]
pub struct StaticNatMappingService {
    v4_store: StaticNatMappingV4Repository,
    v6_store: StaticNatMappingV6Repository,
}

impl StaticNatMappingService {
    pub async fn new(store: LandscapeDBServiceProvider) -> Self {
        let service = Self {
            v4_store: store.static_nat_mapping_v4_store(),
            v6_store: store.static_nat_mapping_v6_store(),
        };

        let v4_empty = service.v4_store.list().await.is_ok_and(|l| l.is_empty());
        let v6_empty = service.v6_store.list().await.is_ok_and(|l| l.is_empty());
        if v4_empty && v6_empty {
            service.init_default_rules().await;
        }

        service.refresh_runtime_rules().await;
        service
    }

    async fn init_default_rules(&self) {
        for config in default_static_mapping_v4_rules() {
            let _ = self.v4_store.set(config).await;
        }
        for config in default_static_mapping_v6_rules() {
            let _ = self.v6_store.set(config).await;
        }
    }

    // --- V4 CRUD ---

    pub async fn list_v4(&self) -> Vec<StaticNatMappingV4Config> {
        self.v4_store.list().await.unwrap_or_default()
    }

    pub async fn find_v4_by_id(&self, id: Uuid) -> Option<StaticNatMappingV4Config> {
        self.v4_store.find_by_id(id).await.ok()?
    }

    pub async fn checked_set_v4(
        &self,
        config: StaticNatMappingV4Config,
    ) -> Result<StaticNatMappingV4Config, LdError> {
        let result = self.v4_store.checked_set(config).await?;
        self.refresh_runtime_rules().await;
        Ok(result)
    }

    pub async fn checked_set_list_v4(
        &self,
        configs: Vec<StaticNatMappingV4Config>,
    ) -> Result<(), LdError> {
        for config in &configs {
            self.v4_store.check_conflict(config).await?;
        }
        for config in configs {
            self.v4_store.checked_set(config).await?;
        }
        self.refresh_runtime_rules().await;
        Ok(())
    }

    pub async fn delete_v4(&self, id: Uuid) {
        if self.find_v4_by_id(id).await.is_some() {
            let _ = self.v4_store.delete(id).await;
            self.refresh_runtime_rules().await;
        }
    }

    pub async fn validate_runtime_target_v4(
        &self,
        config: &StaticNatMappingV4Config,
    ) -> Result<(), LdError> {
        self.v4_store.validate_runtime_target_v4(config).await
    }

    // --- V6 CRUD ---

    pub async fn list_v6(&self) -> Vec<StaticNatMappingV6Config> {
        self.v6_store.list().await.unwrap_or_default()
    }

    pub async fn find_v6_by_id(&self, id: Uuid) -> Option<StaticNatMappingV6Config> {
        self.v6_store.find_by_id(id).await.ok()?
    }

    pub async fn checked_set_v6(
        &self,
        config: StaticNatMappingV6Config,
    ) -> Result<StaticNatMappingV6Config, LdError> {
        let result = self.v6_store.checked_set(config).await?;
        self.refresh_runtime_rules().await;
        Ok(result)
    }

    pub async fn checked_set_list_v6(
        &self,
        configs: Vec<StaticNatMappingV6Config>,
    ) -> Result<(), LdError> {
        for config in &configs {
            self.v6_store.check_conflict(config).await?;
        }
        for config in configs {
            self.v6_store.checked_set(config).await?;
        }
        self.refresh_runtime_rules().await;
        Ok(())
    }

    pub async fn delete_v6(&self, id: Uuid) {
        if self.find_v6_by_id(id).await.is_some() {
            let _ = self.v6_store.delete(id).await;
            self.refresh_runtime_rules().await;
        }
    }

    pub async fn validate_runtime_target_v6(
        &self,
        config: &StaticNatMappingV6Config,
    ) -> Result<(), LdError> {
        self.v6_store.validate_runtime_target_v6(config).await
    }

    // --- Runtime ---

    pub async fn refresh_runtime_rules(&self) {
        let v4_configs = match self.v4_store.list_runtime_configs_v4().await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!("failed to load static NAT v4 runtime configs: {error:?}");
                Vec::new()
            }
        };

        let v6_configs = match self.v6_store.list_runtime_configs_v6().await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!("failed to load static NAT v6 runtime configs: {error:?}");
                Vec::new()
            }
        };

        if let Err(error) = landscape_ebpf::map_setting::nat::reconcile_static_nat4_map(&v4_configs)
        {
            tracing::error!("failed to reconcile static NAT v4 map: {error:?}");
        }

        if let Err(error) = landscape_ebpf::map_setting::nat::reconcile_static_nat6_map(&v6_configs)
        {
            tracing::error!("failed to reconcile static NAT v6 map: {error:?}");
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

fn default_static_mapping_v6_rules() -> Vec<StaticNatMappingV6Config> {
    vec![StaticNatMappingV6Config {
        wan_iface_name: None,
        lan_target: Some(StaticNatV6Target::address(Ipv6Addr::UNSPECIFIED)),
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
