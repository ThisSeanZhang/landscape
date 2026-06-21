use std::collections::{HashMap, HashSet};

use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::error::LdError;
use landscape_common::iface::nat::{
    RuntimeStaticNatMappingV4Config, StaticNatMappingV4Config, StaticNatV4Target,
};
use sea_orm::DatabaseConnection;

use super::entity::{
    StaticNatMappingV4ConfigActiveModel, StaticNatMappingV4ConfigEntity,
    StaticNatMappingV4ConfigModel,
};
use crate::enrolled_device::repository::EnrolledDeviceRepository;
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
    ) -> Result<Vec<RuntimeStaticNatMappingV4Config>, LdError> {
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
    ) -> Result<HashMap<DBId, EnrolledDevice>, LdError> {
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
    ) -> Result<(), LdError> {
        let devices = self.load_devices_for_configs(std::slice::from_ref(config)).await?;
        let lan_ipv4 = resolve_static_nat_v4_target(config, &devices);

        if config.enable && !config.l4_protocols.is_empty() && lan_ipv4.is_none() {
            return Err(LdError::ConfigError(
                "enabled IPv4 static NAT mapping must resolve to an IPv4 target".to_string(),
            ));
        }

        Ok(())
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
