use std::collections::{HashMap, HashSet};

use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::error::LdError;
use landscape_common::iface::nat::{
    RuntimeStaticNatMappingV6Config, StaticNatMappingV6Config, StaticNatV6Target,
};
use landscape_common::ipv6::lan::{
    LanIPv6ServiceConfigV2, LanPrefixGroupConfig, PrefixParentSource,
};
use landscape_common::ipv6::{checked_allocate_subnet, checked_combine_ipv6_prefix_suffix};
use sea_orm::DatabaseConnection;

use super::entity::{
    StaticNatMappingV6ConfigActiveModel, StaticNatMappingV6ConfigEntity,
    StaticNatMappingV6ConfigModel,
};
use crate::enrolled_device::repository::EnrolledDeviceRepository;
use crate::lan_ipv6_v2::repository::LanIPv6V2ServiceRepository;
use crate::repository::Repository;
use crate::DBId;

#[derive(Clone)]
pub struct StaticNatMappingV6Repository {
    db: DatabaseConnection,
}

impl StaticNatMappingV6Repository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn list_runtime_configs_v6(
        &self,
    ) -> Result<Vec<RuntimeStaticNatMappingV6Config>, LdError> {
        let configs: Vec<StaticNatMappingV6Config> = self.list_all().await?;
        let devices = self.load_devices_for_configs(&configs).await?;

        let has_device_target = configs.iter().any(|config| {
            matches!(config.lan_target.as_ref(), Some(StaticNatV6Target::Device { .. }))
        });
        let lan_ipv6_configs = if has_device_target {
            LanIPv6V2ServiceRepository::new(self.db.clone())
                .list_all()
                .await?
                .into_iter()
                .map(|config| (config.iface_name.clone(), config))
                .collect()
        } else {
            HashMap::new()
        };

        Ok(configs
            .into_iter()
            .filter(|config| config.enable)
            .flat_map(|config| {
                resolve_static_nat_mapping_v6_configs(config, &devices, &lan_ipv6_configs)
            })
            .collect())
    }

    async fn load_devices_for_configs(
        &self,
        configs: &[StaticNatMappingV6Config],
    ) -> Result<HashMap<DBId, EnrolledDevice>, LdError> {
        let mut device_ids = HashSet::new();
        for config in configs {
            if let Some(StaticNatV6Target::Device { device_ids: ids }) = config.lan_target.as_ref()
            {
                device_ids.extend(ids);
            }
        }

        let devices = EnrolledDeviceRepository::new(self.db.clone())
            .find_by_ids(device_ids.into_iter().collect())
            .await;
        Ok(devices.into_iter().map(|device| (device.id, device)).collect())
    }

    pub async fn validate_runtime_target_v6(
        &self,
        config: &StaticNatMappingV6Config,
    ) -> Result<(), LdError> {
        let devices = self.load_devices_for_configs(std::slice::from_ref(config)).await?;

        if let Some(StaticNatV6Target::Device { device_ids }) = config.lan_target.as_ref() {
            if config.enable && !config.l4_protocols.is_empty() {
                for device_id in device_ids {
                    if !device_id.is_nil() {
                        match devices.get(device_id) {
                            None => {
                                return Err(LdError::ConfigError(format!(
                                    "device {} referenced in static NAT v6 config does not exist",
                                    device_id
                                )));
                            }
                            Some(device) => {
                                if device.ipv6.is_none() {
                                    return Err(LdError::ConfigError(format!(
                                        "device {} does not have an IPv6 address",
                                        device_id
                                    )));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn resolve_static_nat_mapping_v6_configs(
    config: StaticNatMappingV6Config,
    devices: &HashMap<DBId, EnrolledDevice>,
    lan_ipv6_configs: &HashMap<String, LanIPv6ServiceConfigV2>,
) -> Vec<RuntimeStaticNatMappingV6Config> {
    let lan_ipv6s = resolve_static_nat_v6_targets(&config, devices, lan_ipv6_configs);
    lan_ipv6s
        .into_iter()
        .map(|lan_ipv6| RuntimeStaticNatMappingV6Config {
            port_config: config.port_config.clone(),
            lan_ipv6,
            l4_protocols: config.l4_protocols.clone(),
        })
        .collect()
}

fn resolve_static_nat_v6_targets(
    config: &StaticNatMappingV6Config,
    devices: &HashMap<DBId, EnrolledDevice>,
    lan_ipv6_configs: &HashMap<String, LanIPv6ServiceConfigV2>,
) -> Vec<std::net::Ipv6Addr> {
    match config.lan_target.as_ref() {
        Some(StaticNatV6Target::Address { ipv6 }) => vec![*ipv6],
        Some(StaticNatV6Target::Local) => vec![std::net::Ipv6Addr::UNSPECIFIED],
        Some(StaticNatV6Target::Device { device_ids }) => device_ids
            .iter()
            .filter_map(|device_id| {
                let device = devices.get(device_id)?;
                match resolve_device_ipv6(device, lan_ipv6_configs) {
                    Ok(ip) => Some(ip),
                    Err(e) => {
                        tracing::warn!(
                            "static NAT v6 device {} target unresolved: {}",
                            device_id,
                            e
                        );
                        None
                    }
                }
            })
            .collect(),
        None => vec![],
    }
}

fn resolve_device_ipv6(
    device: &EnrolledDevice,
    lan_ipv6_configs: &HashMap<String, LanIPv6ServiceConfigV2>,
) -> Result<std::net::Ipv6Addr, String> {
    let device_ipv6 = device.ipv6.ok_or_else(|| "device has no IPv6 address".to_string())?;
    let iface_name =
        device.iface_name.as_ref().ok_or_else(|| "device has no interface name".to_string())?;
    let config = lan_ipv6_configs
        .get(iface_name)
        .ok_or_else(|| format!("no LAN IPv6 service config for interface '{iface_name}'"))?;
    let group = select_device_ipv6_group(&config.config.prefix_groups)
        .ok_or_else(|| format!("no NA prefix group configured on interface '{iface_name}'"))?;
    match &group.parent {
        PrefixParentSource::Static { base_prefix, parent_prefix_len } => {
            let pool_index = group.na.as_ref().map(|na| na.pool_index).ok_or_else(|| {
                format!("NA prefix group missing pool_index on interface '{iface_name}'")
            })?;
            let (prefix, _) =
                checked_allocate_subnet(*base_prefix, *parent_prefix_len, 64, pool_index as u128)
                    .ok_or_else(|| {
                    format!("failed to allocate subnet for NA pool on interface '{iface_name}'")
                })?;
            checked_combine_ipv6_prefix_suffix(prefix, 64, device_ipv6).ok_or_else(|| {
                format!(
                    "failed to combine IPv6 prefix/suffix for device on interface '{iface_name}'"
                )
            })
        }
        PrefixParentSource::Pd { .. } => Ok(device_ipv6),
    }
}

fn select_device_ipv6_group(groups: &[LanPrefixGroupConfig]) -> Option<&LanPrefixGroupConfig> {
    groups.iter().find(|group| group.na.is_some())
}

crate::impl_repository!(
    StaticNatMappingV6Repository,
    StaticNatMappingV6ConfigModel,
    StaticNatMappingV6ConfigEntity,
    StaticNatMappingV6ConfigActiveModel,
    StaticNatMappingV6Config,
    DBId
);
