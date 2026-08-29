use std::collections::{HashMap, HashSet};

use landscape_common::config_service::enrolled_device::EnrolledDevice;
use landscape_common::config_service::static_nat::config6::{
    RuntimeStaticNatMappingV6Config, StaticNatMappingV6Config, StaticNatV6Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::error::DbError;
use landscape_common::lan_service::lan_ipv6::{
    checked_allocate_subnet, checked_combine_ipv6_prefix_suffix,
};
use landscape_common::lan_service::lan_ipv6::{
    LanIPv6ServiceConfigV2, LanPrefixGroupConfig, PrefixParentSource,
};
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
        wan_iid: u64,
        dynamic_device_ipv6s: &HashMap<DBId, HashSet<std::net::Ipv6Addr>>,
    ) -> Result<Vec<RuntimeStaticNatMappingV6Config>, DbError> {
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
                resolve_static_nat_mapping_v6_configs(
                    config,
                    &devices,
                    &lan_ipv6_configs,
                    dynamic_device_ipv6s,
                    wan_iid,
                )
            })
            .collect())
    }

    async fn load_devices_for_configs(
        &self,
        configs: &[StaticNatMappingV6Config],
    ) -> Result<HashMap<DBId, EnrolledDevice>, DbError> {
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
    ) -> Result<(), StaticNatError> {
        let devices = self.load_devices_for_configs(std::slice::from_ref(config)).await?;

        if let Some(StaticNatV6Target::Device { device_ids }) = config.lan_target.as_ref() {
            if config.enable && !config.l4_protocols.is_empty() {
                for device_id in device_ids {
                    if !device_id.is_nil() && !devices.contains_key(device_id) {
                        return Err(StaticNatError::DeviceNotFound(*device_id));
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
    dynamic_device_ipv6s: &HashMap<DBId, HashSet<std::net::Ipv6Addr>>,
    wan_iid: u64,
) -> Vec<RuntimeStaticNatMappingV6Config> {
    let lan_ipv6s = resolve_static_nat_v6_targets(
        &config,
        devices,
        lan_ipv6_configs,
        dynamic_device_ipv6s,
        wan_iid,
    );
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
    dynamic_device_ipv6s: &HashMap<DBId, HashSet<std::net::Ipv6Addr>>,
    wan_iid: u64,
) -> Vec<std::net::Ipv6Addr> {
    let local_address = std::net::Ipv6Addr::from(wan_iid as u128);
    match config.lan_target.as_ref() {
        Some(StaticNatV6Target::Address { ipv6 }) if ipv6.is_unspecified() => vec![local_address],
        Some(StaticNatV6Target::Address { ipv6 }) => vec![*ipv6],
        Some(StaticNatV6Target::Local) => vec![local_address],
        Some(StaticNatV6Target::Device { device_ids }) => {
            resolve_device_ipv6s(device_ids, devices, lan_ipv6_configs, dynamic_device_ipv6s)
        }
        None => vec![],
    }
}

fn resolve_device_ipv6s(
    device_ids: &[DBId],
    devices: &HashMap<DBId, EnrolledDevice>,
    lan_ipv6_configs: &HashMap<String, LanIPv6ServiceConfigV2>,
    dynamic_device_ipv6s: &HashMap<DBId, HashSet<std::net::Ipv6Addr>>,
) -> Vec<std::net::Ipv6Addr> {
    let mut targets_by_suffix = HashMap::<u64, std::net::Ipv6Addr>::new();

    // Configured IA_NA targets come from the enrolled-device database and do
    // not depend on the best-effort dynamic address cache. They are also
    // authoritative when an observed address has the same suffix.
    for device_id in device_ids {
        let Some(device) = devices.get(device_id) else {
            continue;
        };
        match resolve_device_ipv6(device, lan_ipv6_configs) {
            Ok(ip) => {
                targets_by_suffix.entry(ipv6_suffix(ip)).or_insert(ip);
            }
            Err(error) => {
                tracing::warn!(
                    "static NAT v6 device {} configured target unresolved: {}",
                    device_id,
                    error
                );
            }
        }
    }

    // Merge observed RA/SLAAC addresses when available. Missing or delayed
    // observations must not suppress the database-backed IA_NA targets above.
    for device_id in device_ids {
        if !devices.contains_key(device_id) {
            continue;
        }
        let Some(dynamic_ips) = dynamic_device_ipv6s.get(device_id) else {
            continue;
        };
        let mut dynamic_ips: Vec<_> = dynamic_ips.iter().copied().collect();
        dynamic_ips.sort_unstable();
        for ip in dynamic_ips {
            targets_by_suffix.entry(ipv6_suffix(ip)).or_insert(ip);
        }
    }

    let mut targets: Vec<_> = targets_by_suffix.into_iter().collect();
    targets.sort_unstable_by_key(|(suffix, _)| *suffix);
    targets.into_iter().map(|(_, ip)| ip).collect()
}

fn ipv6_suffix(ip: std::net::Ipv6Addr) -> u64 {
    u128::from(ip) as u64
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

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::config_service::static_nat::config6::StaticNatV6PortConfig;
    use landscape_common::lan_service::lan_ipv6::{
        IPv6ServiceMode, LanIPv6ConfigV2, NaPrefixConfig, RouterFlags,
    };
    use landscape_common::net::MacAddr;
    use sea_orm::prelude::Uuid;

    fn config(target: StaticNatV6Target) -> StaticNatMappingV6Config {
        StaticNatMappingV6Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            port_config: StaticNatV6PortConfig::Ports { ports: vec![53] },
            lan_target: Some(target),
            l4_protocols: vec![17],
            update_at: 0.0,
        }
    }

    #[test]
    fn local_and_legacy_unspecified_address_resolve_to_wan_iid() {
        let wan_iid = 0x1234_5678_9abc_def0;
        let expected = std::net::Ipv6Addr::from(wan_iid as u128);
        let devices = HashMap::new();
        let lan_configs = HashMap::new();

        for target in
            [StaticNatV6Target::Local, StaticNatV6Target::address(std::net::Ipv6Addr::UNSPECIFIED)]
        {
            assert_eq!(
                resolve_static_nat_v6_targets(
                    &config(target),
                    &devices,
                    &lan_configs,
                    &HashMap::new(),
                    wan_iid,
                ),
                vec![expected]
            );
        }
    }

    #[test]
    fn suffix_only_address_is_not_replaced_by_wan_iid() {
        let target = "::1234".parse().unwrap();
        assert_eq!(
            resolve_static_nat_v6_targets(
                &config(StaticNatV6Target::address(target)),
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                0x5678,
            ),
            vec![target]
        );
    }

    #[test]
    fn explicit_wan_namespace_address_remains_a_valid_target() {
        let target = "::8000:0:0:1234".parse().unwrap();
        assert_eq!(
            resolve_static_nat_v6_targets(
                &config(StaticNatV6Target::address(target)),
                &HashMap::new(),
                &HashMap::new(),
                &HashMap::new(),
                0x8000_0000_0000_5678,
            ),
            vec![target]
        );
    }

    #[test]
    fn legacy_device_in_wan_namespace_remains_a_valid_target() {
        let device_id = Uuid::new_v4();
        let target = "::8000:0:0:1234".parse().unwrap();
        let device = EnrolledDevice {
            id: device_id,
            update_at: 0.0,
            iface_name: Some("lan0".to_string()),
            name: "legacy".to_string(),
            fake_name: None,
            remark: None,
            hostname: None,
            mac: MacAddr::from([0, 1, 2, 3, 4, 5]),
            ipv4: None,
            ipv6: Some(target),
            tag: Vec::new(),
            dhcp_custom_options: Vec::new(),
            dhcp_filter_options: Vec::new(),
        };
        let lan_config = LanIPv6ServiceConfigV2 {
            iface_name: "lan0".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 600,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "na".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "wan0".to_string(),
                        expected_pd_len_snapshot: 56,
                    },
                    ra: None,
                    na: Some(NaPrefixConfig { pool_index: 1 }),
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        };

        assert_eq!(
            resolve_static_nat_v6_targets(
                &config(StaticNatV6Target::Device { device_ids: vec![device_id] }),
                &HashMap::from([(device_id, device)]),
                &HashMap::from([("lan0".to_string(), lan_config)]),
                &HashMap::new(),
                0x8000_0000_0000_5678,
            ),
            vec![target]
        );
    }

    #[test]
    fn device_target_merges_configured_na_and_dynamic_ra_suffixes() {
        let device_id = Uuid::new_v4();
        let configured = "::100".parse().unwrap();
        let dynamic_a = "2001:db8:1::200".parse().unwrap();
        let dynamic_b = "fd00:1::300".parse().unwrap();
        let device = enrolled_device(device_id, configured);
        let lan_config = pd_lan_config();
        let dynamic = HashMap::from([(device_id, HashSet::from([dynamic_a, dynamic_b]))]);

        let targets = resolve_static_nat_v6_targets(
            &config(StaticNatV6Target::Device { device_ids: vec![device_id] }),
            &HashMap::from([(device_id, device)]),
            &HashMap::from([("lan0".to_string(), lan_config)]),
            &dynamic,
            0,
        );

        assert_eq!(
            targets.into_iter().collect::<HashSet<_>>(),
            HashSet::from([configured, dynamic_a, dynamic_b,])
        );
    }

    #[test]
    fn configured_na_wins_when_dynamic_address_has_the_same_suffix() {
        let device_id = Uuid::new_v4();
        let configured = "::100".parse().unwrap();
        let dynamic_same_suffix = "2001:db8:1::100".parse().unwrap();
        let dynamic = HashMap::from([(device_id, HashSet::from([dynamic_same_suffix]))]);

        let targets = resolve_static_nat_v6_targets(
            &config(StaticNatV6Target::Device { device_ids: vec![device_id] }),
            &HashMap::from([(device_id, enrolled_device(device_id, configured))]),
            &HashMap::from([("lan0".to_string(), pd_lan_config())]),
            &dynamic,
            0,
        );

        assert_eq!(targets, vec![configured]);
    }

    fn enrolled_device(device_id: Uuid, ipv6: std::net::Ipv6Addr) -> EnrolledDevice {
        EnrolledDevice {
            id: device_id,
            update_at: 0.0,
            iface_name: Some("lan0".to_string()),
            name: "device".to_string(),
            fake_name: None,
            remark: None,
            hostname: None,
            mac: MacAddr::from([0, 1, 2, 3, 4, 5]),
            ipv4: None,
            ipv6: Some(ipv6),
            tag: Vec::new(),
            dhcp_custom_options: Vec::new(),
            dhcp_filter_options: Vec::new(),
        }
    }

    fn pd_lan_config() -> LanIPv6ServiceConfigV2 {
        LanIPv6ServiceConfigV2 {
            iface_name: "lan0".to_string(),
            enable: true,
            config: LanIPv6ConfigV2 {
                mode: IPv6ServiceMode::Stateful,
                ad_interval: 600,
                lifetime: 300,
                ra_flag: RouterFlags::from(0xc0),
                prefix_groups: vec![LanPrefixGroupConfig {
                    group_id: "na".to_string(),
                    parent: PrefixParentSource::Pd {
                        depend_iface: "wan0".to_string(),
                        expected_pd_len_snapshot: 56,
                    },
                    ra: None,
                    na: Some(NaPrefixConfig { pool_index: 1 }),
                    pd: None,
                }],
                dhcpv6: None,
            },
            update_at: 0.0,
        }
    }
}
