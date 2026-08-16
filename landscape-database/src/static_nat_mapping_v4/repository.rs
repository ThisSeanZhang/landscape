use std::collections::{HashMap, HashSet};

use landscape_common::config_service::enrolled_device::EnrolledDevice;
use landscape_common::config_service::static_nat::config4::{
    RuntimeStaticNatMappingV4Config, StaticNatMappingV4Config, StaticNatV4Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::error::DbError;
use migration::Expr;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Value};

use super::entity::{
    StaticNatMappingV4ConfigActiveModel, StaticNatMappingV4ConfigEntity,
    StaticNatMappingV4ConfigModel,
};
use crate::enrolled_device::repository::EnrolledDeviceRepository;
use crate::nat::entity::{Column as NatCol, NatServiceConfigEntity};
use crate::repository::Repository;
use crate::DBId;

#[derive(Clone)]
pub struct StaticNatMappingV4Repository {
    db: DatabaseConnection,
}

impl StaticNatMappingV4Repository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn list_runtime_configs_v4(
        &self,
    ) -> Result<Vec<RuntimeStaticNatMappingV4Config>, DbError> {
        let configs: Vec<StaticNatMappingV4Config> = self.list_all().await?;
        let devices = self.load_devices_for_configs(&configs).await?;

        Ok(configs
            .into_iter()
            .filter(|config| config.enable)
            .filter_map(|config| resolve_static_nat_mapping_v4_config(config, &devices))
            .collect())
    }

    async fn load_devices_for_configs(
        &self,
        configs: &[StaticNatMappingV4Config],
    ) -> Result<HashMap<DBId, EnrolledDevice>, DbError> {
        let mut device_ids = HashSet::new();
        for config in configs {
            if let Some(StaticNatV4Target::Device { device_id }) = config.lan_target.as_ref() {
                device_ids.insert(*device_id);
            }
        }

        let devices = EnrolledDeviceRepository::new(self.db.clone())
            .find_by_ids(device_ids.into_iter().collect())
            .await;
        Ok(devices.into_iter().map(|device| (device.id, device)).collect())
    }

    pub async fn validate_runtime_target_v4(
        &self,
        config: &StaticNatMappingV4Config,
    ) -> Result<(), StaticNatError> {
        let devices = self.load_devices_for_configs(std::slice::from_ref(config)).await?;
        let lan_ipv4 = resolve_static_nat_v4_target(config, &devices);

        if config.enable && !config.l4_protocols.is_empty() && lan_ipv4.is_none() {
            return Err(StaticNatError::InvalidTarget(
                "enabled IPv4 static NAT mapping must resolve to an IPv4 target".to_string(),
            ));
        }

        Ok(())
    }

    pub async fn has_dynamic_port_conflict(
        &self,
        config: &StaticNatMappingV4Config,
    ) -> Result<bool, StaticNatError> {
        let l4_json = serde_json::to_string(&config.l4_protocols)
            .map_err(|e| StaticNatError::Internal(DbError::Internal(e.to_string())))?;
        let ports_json = serde_json::to_string(&config.mapping_pair_ports)
            .map_err(|e| StaticNatError::Internal(DbError::Internal(e.to_string())))?;

        let expr = Expr::cust_with_values(
            "EXISTS (
                SELECT 1 FROM json_each(?) AS proto, json_each(?) AS mp
                WHERE (proto.value = 6  AND json_extract(mp.value, '$.wan_port') BETWEEN tcp_range_start AND tcp_range_end)
                   OR (proto.value = 17 AND json_extract(mp.value, '$.wan_port') BETWEEN udp_range_start AND udp_range_end)
            )",
            vec![
                Value::String(Some(Box::from(l4_json))),
                Value::String(Some(Box::from(ports_json))),
            ],
        );

        let res = NatServiceConfigEntity::find()
            .filter(NatCol::Enable.eq(true))
            .filter(expr)
            .one(&self.db)
            .await
            .map_err(DbError::from)?;
        Ok(res.is_some())
    }
}

fn resolve_static_nat_mapping_v4_config(
    config: StaticNatMappingV4Config,
    devices: &HashMap<DBId, EnrolledDevice>,
) -> Option<RuntimeStaticNatMappingV4Config> {
    let lan_ipv4 = resolve_static_nat_v4_target(&config, devices)?;
    Some(RuntimeStaticNatMappingV4Config {
        mapping_pair_ports: config.mapping_pair_ports,
        lan_ipv4,
        l4_protocols: config.l4_protocols,
    })
}

fn resolve_static_nat_v4_target(
    config: &StaticNatMappingV4Config,
    devices: &HashMap<DBId, EnrolledDevice>,
) -> Option<std::net::Ipv4Addr> {
    match config.lan_target.as_ref() {
        Some(StaticNatV4Target::Address { ipv4 }) => Some(*ipv4),
        Some(StaticNatV4Target::Local) => Some(std::net::Ipv4Addr::UNSPECIFIED),
        Some(StaticNatV4Target::Device { device_id }) => {
            let device = devices.get(device_id)?;
            device.ipv4
        }
        None => None,
    }
}

crate::impl_repository!(
    StaticNatMappingV4Repository,
    StaticNatMappingV4ConfigModel,
    StaticNatMappingV4ConfigEntity,
    StaticNatMappingV4ConfigActiveModel,
    StaticNatMappingV4Config,
    DBId
);

#[cfg(test)]
mod tests {
    use landscape_common::config_service::static_nat::config::StaticMapPair;
    use landscape_common::config_service::static_nat::config4::{
        StaticNatMappingV4Config, StaticNatV4Target,
    };
    use landscape_common::database::LandscapeStore;
    use landscape_common::wan_service::nat::config::{NatConfig, NatServiceConfig};
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    fn make_nat_config(
        iface: &str,
        tcp_range: (u16, u16),
        udp_range: (u16, u16),
    ) -> NatServiceConfig {
        NatServiceConfig {
            iface_name: iface.to_string(),
            enable: true,
            nat_config: NatConfig {
                tcp_range: tcp_range.0..tcp_range.1,
                udp_range: udp_range.0..udp_range.1,
                icmp_in_range: 0..0,
            },
            update_at: 0.0,
        }
    }

    async fn insert_nat_service(provider: &LandscapeDBServiceProvider, config: NatServiceConfig) {
        provider.nat_service_store().set(config).await.unwrap();
    }

    #[tokio::test]
    async fn conflict_when_wan_port_inside_dynamic_range() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_nat_service(&provider, make_nat_config("wan0", (32768, 65535), (32768, 65535)))
            .await;

        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 40000, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![6],
            update_at: 0.0,
        };

        let repo = provider.static_nat_mapping_v4_store();
        let result = repo.has_dynamic_port_conflict(&config).await.unwrap();
        assert!(result, "TCP port 40000 should conflict with range 32768-65535");
    }

    #[tokio::test]
    async fn no_conflict_when_wan_port_outside_dynamic_range() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_nat_service(&provider, make_nat_config("wan0", (32768, 65535), (32768, 65535)))
            .await;

        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 80, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![6],
            update_at: 0.0,
        };

        let repo = provider.static_nat_mapping_v4_store();
        let result = repo.has_dynamic_port_conflict(&config).await.unwrap();
        assert!(!result, "TCP port 80 should not conflict with range 32768-65535");
    }

    #[tokio::test]
    async fn no_conflict_when_nat_disabled() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let mut cfg = make_nat_config("wan0", (32768, 65535), (32768, 65535));
        cfg.enable = false;
        insert_nat_service(&provider, cfg).await;

        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 40000, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![6],
            update_at: 0.0,
        };

        let repo = provider.static_nat_mapping_v4_store();
        let result = repo.has_dynamic_port_conflict(&config).await.unwrap();
        assert!(!result, "disabled NAT should not cause conflict");
    }

    #[tokio::test]
    async fn conflict_matches_correct_protocol_range() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_nat_service(&provider, make_nat_config("wan0", (32768, 65535), (10000, 20000)))
            .await;

        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 15000, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![17],
            update_at: 0.0,
        };

        let repo = provider.static_nat_mapping_v4_store();
        let result = repo.has_dynamic_port_conflict(&config).await.unwrap();
        assert!(result, "UDP port 15000 should conflict with UDP range 10000-20000");
    }

    #[tokio::test]
    async fn no_conflict_when_protocol_range_mismatch() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_nat_service(&provider, make_nat_config("wan0", (32768, 65535), (10000, 20000)))
            .await;

        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 40000, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![17],
            update_at: 0.0,
        };

        let repo = provider.static_nat_mapping_v4_store();
        let result = repo.has_dynamic_port_conflict(&config).await.unwrap();
        assert!(!result, "UDP port 40000 should not conflict with UDP range 10000-20000");
    }

    #[tokio::test]
    async fn boundary_port_triggers_conflict() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_nat_service(&provider, make_nat_config("wan0", (32768, 65535), (32768, 65535)))
            .await;

        let config = StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port: 32768, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![6],
            update_at: 0.0,
        };

        let repo = provider.static_nat_mapping_v4_store();
        let result = repo.has_dynamic_port_conflict(&config).await.unwrap();
        assert!(result, "port at range start should be detected");
    }
}
