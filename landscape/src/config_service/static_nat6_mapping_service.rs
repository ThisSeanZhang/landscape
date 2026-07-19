use std::sync::Arc;

use landscape_common::config_service::static_nat::config6::{
    StaticNatMappingV6Config, StaticNatV6PortConfig, StaticNatV6Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::LandscapeStore;
use landscape_common::error::LdError;
use landscape_common::event::hub::EnrolledDeviceEventReader;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::static_nat_mapping_v6::repository::StaticNatMappingV6Repository;
use uuid::Uuid;

#[derive(Clone)]
pub struct StaticNat6MappingService {
    store: StaticNatMappingV6Repository,
    wan_iid: Arc<u64>,
}

impl StaticNat6MappingService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        device_reader: EnrolledDeviceEventReader,
        wan_iid: Arc<u64>,
    ) -> Self {
        let service = Self {
            store: store_provider.static_nat_mapping_v6_store(),
            wan_iid,
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
        for config in default_static_mapping_v6_rules() {
            let _ = self.store.set(config).await;
        }
    }

    // --- V6 CRUD ---

    pub async fn list(&self) -> Vec<StaticNatMappingV6Config> {
        self.store.list().await.unwrap_or_default()
    }

    pub async fn find_by_id(&self, id: Uuid) -> Option<StaticNatMappingV6Config> {
        self.store.find_by_id(id).await.ok()?
    }

    pub async fn checked_set(
        &self,
        config: StaticNatMappingV6Config,
    ) -> Result<StaticNatMappingV6Config, LdError> {
        let result = self.store.checked_set(config).await?;
        self.refresh_runtime_rules().await;
        Ok(result)
    }

    pub async fn checked_set_list(
        &self,
        configs: Vec<StaticNatMappingV6Config>,
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
        config: &StaticNatMappingV6Config,
    ) -> Result<(), StaticNatError> {
        self.store.validate_runtime_target_v6(config).await
    }

    // --- Runtime ---

    pub async fn refresh_runtime_rules(&self) {
        let configs = match self.store.list_runtime_configs_v6(*self.wan_iid).await {
            Ok(configs) => configs,
            Err(error) => {
                tracing::error!("failed to load static NAT v6 runtime configs: {error:?}");
                Vec::new()
            }
        };

        if let Err(error) = landscape_ebpf::map_setting::nat::reconcile_static_nat6_map(&configs) {
            tracing::error!("failed to reconcile static NAT v6 map: {error:?}");
        }
    }
}

fn default_static_mapping_v6_rules() -> Vec<StaticNatMappingV6Config> {
    vec![StaticNatMappingV6Config {
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
