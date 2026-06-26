use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::error::LdError;
use landscape_common::iface::nat::{
    RuntimeStaticNatMappingConfig, StaticNatMappingConfig, StaticNatTarget,
};
use landscape_common::ipv6::lan::{
    LanIPv6ServiceConfigV2, LanPrefixGroupConfig, PrefixParentSource,
};
use landscape_common::ipv6::{checked_allocate_subnet, checked_combine_ipv6_prefix_suffix};
use sea_orm::DatabaseConnection;

use super::entity::{
    StaticNatMappingConfigActiveModel, StaticNatMappingConfigEntity, StaticNatMappingConfigModel,
};
use crate::enrolled_device::repository::EnrolledDeviceRepository;
use crate::lan_ipv6_v2::repository::LanIPv6V2ServiceRepository;
use crate::repository::Repository;
use crate::DBId;

#[derive(Clone)]
pub struct StaticNatMappingConfigRepository {
    db: DatabaseConnection,
}

impl StaticNatMappingConfigRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn list_runtime_configs(
        &self,
    ) -> Result<Vec<RuntimeStaticNatMappingConfig>, LdError> {
        let configs = self.list_all().await?;
        let devices = self.load_devices_for_configs(&configs).await?;

        let has_device_target = configs.iter().any(|config| {
            matches!(config.lan_target.as_ref(), Some(StaticNatTarget::Device { .. }))
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
            .map(|config| resolve_static_nat_mapping_config(config, &devices, &lan_ipv6_configs))
            .collect())
    }

    async fn load_devices_for_configs(
        &self,
        configs: &[StaticNatMappingConfig],
    ) -> Result<HashMap<DBId, EnrolledDevice>, LdError> {
        let mut device_ids = HashSet::new();
        for config in configs {
            if let Some(StaticNatTarget::Device { device_id }) = config.lan_target.as_ref() {
                device_ids.insert(*device_id);
            }
        }

        let devices = EnrolledDeviceRepository::new(self.db.clone())
            .find_by_ids(device_ids.into_iter().collect())
            .await;
        Ok(devices.into_iter().map(|device| (device.id, device)).collect())
    }

    pub async fn validate_runtime_target(
        &self,
        config: &StaticNatMappingConfig,
    ) -> Result<(), LdError> {
        let devices = self.load_devices_for_configs(std::slice::from_ref(config)).await?;
        if let Some(StaticNatTarget::Device { device_id }) = config.lan_target.as_ref() {
            if !device_id.is_nil() && config.enable {
                let device = devices.get(device_id).ok_or_else(|| {
                    LdError::ConfigError(format!(
                        "device {} referenced in static NAT config does not exist",
                        device_id
                    ))
                })?;
                if !config.ipv4_l4_protocol.is_empty() && device.ipv4.is_none() {
                    return Err(LdError::ConfigError(format!(
                        "device {} does not have an IPv4 address",
                        device_id
                    )));
                }
                if !config.ipv6_l4_protocol.is_empty() && device.ipv6.is_none() {
                    return Err(LdError::ConfigError(format!(
                        "device {} does not have an IPv6 address",
                        device_id
                    )));
                }
            }
        }

        Ok(())
    }
}

fn resolve_static_nat_mapping_config(
    config: StaticNatMappingConfig,
    devices: &HashMap<DBId, EnrolledDevice>,
    lan_ipv6_configs: &HashMap<String, LanIPv6ServiceConfigV2>,
) -> RuntimeStaticNatMappingConfig {
    let (lan_ipv4, lan_ipv6) = resolve_static_nat_target(&config, devices, lan_ipv6_configs);
    RuntimeStaticNatMappingConfig {
        mapping_pair_ports: config.mapping_pair_ports,
        lan_ipv4,
        lan_ipv6,
        ipv4_l4_protocol: config.ipv4_l4_protocol,
        ipv6_l4_protocol: config.ipv6_l4_protocol,
    }
}

fn resolve_static_nat_target(
    config: &StaticNatMappingConfig,
    devices: &HashMap<DBId, EnrolledDevice>,
    lan_ipv6_configs: &HashMap<String, LanIPv6ServiceConfigV2>,
) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    match config.lan_target.as_ref() {
        Some(StaticNatTarget::Address { ipv4, ipv6 }) => (*ipv4, *ipv6),
        Some(StaticNatTarget::Local) => (Some(Ipv4Addr::UNSPECIFIED), Some(Ipv6Addr::UNSPECIFIED)),
        Some(StaticNatTarget::Device { device_id }) => {
            let Some(device) = devices.get(device_id) else {
                tracing::warn!("static NAT device target unresolved: device {device_id} not found");
                return (None, None);
            };
            let ipv6 = match resolve_device_ipv6(device, lan_ipv6_configs) {
                Ok(ip) => Some(ip),
                Err(e) => {
                    tracing::warn!("static NAT device {} target unresolved: {}", device_id, e);
                    None
                }
            };
            (device.ipv4, ipv6)
        }
        None => (None, None),
    }
}

fn resolve_device_ipv6(
    device: &EnrolledDevice,
    lan_ipv6_configs: &HashMap<String, LanIPv6ServiceConfigV2>,
) -> Result<Ipv6Addr, String> {
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
    StaticNatMappingConfigRepository,
    StaticNatMappingConfigModel,
    StaticNatMappingConfigEntity,
    StaticNatMappingConfigActiveModel,
    StaticNatMappingConfig,
    DBId
);
