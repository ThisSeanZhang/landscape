use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::Ipv6Addr,
};

use landscape_common::config_service::enrolled_device::EnrolledDevice;
use landscape_common::config_service::static_nat::config6::{
    RuntimeStaticNatMappingV6Config, StaticNatMappingV6Config, StaticNatV6Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use sea_orm::DatabaseConnection;

use super::entity::{
    StaticNatMappingV6ConfigActiveModel, StaticNatMappingV6ConfigEntity,
    StaticNatMappingV6ConfigModel,
};
use crate::DBId;
use crate::enrolled_device::repository::EnrolledDeviceRepository;

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
        dynamic_device_ipv6s: &HashMap<DBId, HashSet<Ipv6Addr>>,
    ) -> Result<Vec<RuntimeStaticNatMappingV6Config>, DbError> {
        let configs: Vec<StaticNatMappingV6Config> = self.list().await?;

        Ok(configs
            .into_iter()
            .filter(|config| config.enable)
            .flat_map(|config| {
                resolve_static_nat_mapping_v6_configs(config, dynamic_device_ipv6s, wan_iid)
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
            .find_ids(device_ids.into_iter().collect())
            .await?;
        Ok(devices.into_iter().map(|device| (device.id, device)).collect())
    }

    pub async fn validate_runtime_target_v6(
        &self,
        config: &StaticNatMappingV6Config,
    ) -> Result<(), StaticNatError> {
        let devices = self.load_devices_for_configs(std::slice::from_ref(config)).await?;

        if let Some(StaticNatV6Target::Device { device_ids }) = config.lan_target.as_ref()
            && config.enable
            && !config.l4_protocols.is_empty()
        {
            for device_id in device_ids {
                if !device_id.is_nil() && !devices.contains_key(device_id) {
                    return Err(StaticNatError::DeviceNotFound(*device_id));
                }
            }
        }

        Ok(())
    }
}

fn resolve_static_nat_mapping_v6_configs(
    config: StaticNatMappingV6Config,
    dynamic_device_ipv6s: &HashMap<DBId, HashSet<Ipv6Addr>>,
    wan_iid: u64,
) -> Vec<RuntimeStaticNatMappingV6Config> {
    let lan_ipv6s = resolve_static_nat_v6_targets(&config, dynamic_device_ipv6s, wan_iid);
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
    dynamic_device_ipv6s: &HashMap<DBId, HashSet<Ipv6Addr>>,
    wan_iid: u64,
) -> Vec<Ipv6Addr> {
    let local_address = Ipv6Addr::from(wan_iid as u128);
    match config.lan_target.as_ref() {
        Some(StaticNatV6Target::Address { ipv6 }) if ipv6.is_unspecified() => vec![local_address],
        Some(StaticNatV6Target::Address { ipv6 }) if ipv6.is_unique_local() => vec![*ipv6],
        Some(StaticNatV6Target::Address { ipv6 }) => vec![suffix_only_addr(*ipv6)],
        Some(StaticNatV6Target::Local) => vec![local_address],
        Some(StaticNatV6Target::Device { device_ids }) => {
            resolve_device_ipv6s(device_ids, dynamic_device_ipv6s)
        }
        None => vec![],
    }
}

#[derive(Default)]
struct SuffixTargets {
    ula: Option<Ipv6Addr>,
    gua: Option<Ipv6Addr>,
}

fn resolve_device_ipv6s(
    device_ids: &[DBId],
    dynamic_device_ipv6s: &HashMap<DBId, HashSet<Ipv6Addr>>,
) -> Vec<Ipv6Addr> {
    let mut targets_by_suffix = BTreeMap::<u64, SuffixTargets>::new();

    for device_id in device_ids {
        let Some(observed) = dynamic_device_ipv6s.get(device_id) else {
            continue;
        };
        for ip in observed {
            let targets = targets_by_suffix.entry(ipv6_suffix(*ip)).or_default();
            if ip.is_unique_local() {
                keep_min(&mut targets.ula, *ip);
            } else {
                keep_min(&mut targets.gua, *ip);
            }
        }
    }

    targets_by_suffix
        .into_values()
        .filter_map(|targets| targets.ula.or_else(|| targets.gua.map(suffix_only_addr)))
        .collect()
}

fn keep_min(slot: &mut Option<Ipv6Addr>, candidate: Ipv6Addr) {
    if slot.is_none_or(|current| candidate < current) {
        *slot = Some(candidate);
    }
}

fn ipv6_suffix(ip: Ipv6Addr) -> u64 {
    u128::from(ip) as u64
}

fn suffix_only_addr(ip: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(ipv6_suffix(ip) as u128)
}

crate::impl_repository!(
    StaticNatMappingV6Repository,
    StaticNatMappingV6ConfigModel,
    StaticNatMappingV6ConfigEntity,
    StaticNatMappingV6ConfigActiveModel,
    StaticNatMappingV6Config,
    DBId
);

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<StaticNatMappingV6Config>
    for StaticNatMappingV6Repository
{
    async fn check_zone(
        &self,
        _config: &StaticNatMappingV6Config,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }

    async fn validate_cross(
        &self,
        config: &mut StaticNatMappingV6Config,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        crate::wan_link::repository::resolve_wan_link_binding(
            self.db.clone(),
            &mut config.wan_link_id,
            &mut config.wan_iface_name,
        )
        .await?;
        self.validate_runtime_target_v6(config).await.map_err(|e| {
            landscape_common::service::ServiceConfigError::InvalidConfig { reason: e.to_string() }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::config_service::static_nat::config6::StaticNatV6PortConfig;
    use sea_orm::prelude::Uuid;

    fn config(target: StaticNatV6Target) -> StaticNatMappingV6Config {
        StaticNatMappingV6Config {
            id: Uuid::new_v4(),
            name: None,
            enable: true,
            remark: String::new(),
            wan_link_id: None,
            wan_iface_name: None,
            port_config: StaticNatV6PortConfig::Ports { ports: vec![53] },
            lan_target: Some(target),
            l4_protocols: vec![17],
            update_at: 0.0,
        }
    }

    fn addr(prefix: &str, suffix: u64) -> Ipv6Addr {
        let base: Ipv6Addr = prefix.parse().expect("valid prefix");
        Ipv6Addr::from((u128::from(base) & (!0u128 << 64)) | suffix as u128)
    }

    fn ula(suffix: u64) -> Ipv6Addr {
        addr("fd00:1::", suffix)
    }

    fn gua(suffix: u64) -> Ipv6Addr {
        addr("2001:db8:1::", suffix)
    }

    fn suffix_only(suffix: u64) -> Ipv6Addr {
        Ipv6Addr::from(suffix as u128)
    }

    fn cache(entries: Vec<(Uuid, Vec<Ipv6Addr>)>) -> HashMap<DBId, HashSet<Ipv6Addr>> {
        entries.into_iter().map(|(id, ips)| (id, ips.into_iter().collect())).collect()
    }

    fn resolve(
        target: StaticNatV6Target,
        cache: &HashMap<DBId, HashSet<Ipv6Addr>>,
    ) -> Vec<Ipv6Addr> {
        resolve_static_nat_v6_targets(&config(target), cache, 0)
    }

    #[test]
    fn local_and_legacy_unspecified_address_resolve_to_wan_iid() {
        let wan_iid = 0x1234_5678_9abc_def0;
        let expected = Ipv6Addr::from(wan_iid as u128);

        for target in [StaticNatV6Target::Local, StaticNatV6Target::address(Ipv6Addr::UNSPECIFIED)]
        {
            assert_eq!(
                resolve_static_nat_v6_targets(&config(target), &HashMap::new(), wan_iid),
                vec![expected]
            );
        }
    }

    #[test]
    fn suffix_only_address_is_not_replaced_by_wan_iid() {
        let target = "::1234".parse().unwrap();
        assert_eq!(resolve(StaticNatV6Target::address(target), &HashMap::new()), vec![target]);
    }

    #[test]
    fn ula_address_target_keeps_its_prefix() {
        let target = ula(0x1234);
        assert_eq!(resolve(StaticNatV6Target::address(target), &HashMap::new()), vec![target]);
    }

    #[test]
    fn gua_address_target_uses_zero_prefix() {
        let target = gua(0x1234);
        assert_eq!(
            resolve(StaticNatV6Target::address(target), &HashMap::new()),
            vec![suffix_only(0x1234)]
        );
    }

    #[test]
    fn device_target_prefers_ula_over_gua_for_the_same_suffix() {
        let device_id = Uuid::new_v4();
        let cache = cache(vec![(device_id, vec![gua(0x100), ula(0x100)])]);

        assert_eq!(
            resolve(StaticNatV6Target::Device { device_ids: vec![device_id] }, &cache),
            vec![ula(0x100)]
        );
    }

    #[test]
    fn device_target_uses_zero_prefix_for_gua_only() {
        let device_id = Uuid::new_v4();
        let cache = cache(vec![(device_id, vec![gua(0x100)])]);

        assert_eq!(
            resolve(StaticNatV6Target::Device { device_ids: vec![device_id] }, &cache),
            vec![suffix_only(0x100)]
        );
    }

    #[test]
    fn device_target_keeps_distinct_suffixes() {
        let device_id = Uuid::new_v4();
        let cache = cache(vec![(device_id, vec![ula(0x100), gua(0x200)])]);

        assert_eq!(
            resolve(StaticNatV6Target::Device { device_ids: vec![device_id] }, &cache),
            vec![ula(0x100), suffix_only(0x200)]
        );
    }

    #[test]
    fn device_target_picks_the_lowest_ula_for_a_suffix() {
        let device_id = Uuid::new_v4();
        let lower = addr("fd00:1::", 0x100);
        let higher = addr("fd00:2::", 0x100);
        let cache = cache(vec![(device_id, vec![higher, lower])]);

        assert_eq!(
            resolve(StaticNatV6Target::Device { device_ids: vec![device_id] }, &cache),
            vec![lower]
        );
    }

    #[test]
    fn device_target_merges_multiple_device_ids_by_suffix() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let cache = cache(vec![(first, vec![ula(0x100)]), (second, vec![gua(0x100), gua(0x200)])]);

        assert_eq!(
            resolve(StaticNatV6Target::Device { device_ids: vec![first, second] }, &cache),
            vec![ula(0x100), suffix_only(0x200)]
        );
    }

    #[test]
    fn device_target_without_observed_addresses_emits_nothing() {
        let device_id = Uuid::new_v4();
        let cache = cache(vec![]);

        assert_eq!(
            resolve(StaticNatV6Target::Device { device_ids: vec![device_id] }, &cache),
            Vec::<Ipv6Addr>::new()
        );
    }

    #[test]
    fn device_target_ignores_unselected_devices() {
        let selected = Uuid::new_v4();
        let other = Uuid::new_v4();
        let cache = cache(vec![(selected, vec![ula(0x100)]), (other, vec![ula(0x200)])]);

        assert_eq!(
            resolve(StaticNatV6Target::Device { device_ids: vec![selected] }, &cache),
            vec![ula(0x100)]
        );
    }
}
