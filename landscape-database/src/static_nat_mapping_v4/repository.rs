use std::collections::{HashMap, HashSet};

use landscape_common::config_service::enrolled_device::EnrolledDevice;
use landscape_common::config_service::static_nat::config4::{
    RuntimeStaticNatMappingV4Config, StaticNatMappingV4Config, StaticNatV4Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::service::ServiceConfigError;
use landscape_common::wan_link::RuntimeWanLinkConfig;
use landscape_common::wan_service::nat::config::NatConfig;
use sea_orm::DatabaseConnection;

use super::entity::{
    StaticNatMappingV4ConfigActiveModel, StaticNatMappingV4ConfigEntity,
    StaticNatMappingV4ConfigModel,
};
use crate::DBId;
use crate::enrolled_device::repository::EnrolledDeviceRepository;
use crate::wan_link::repository::WanLinkRepository;

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
        let configs: Vec<StaticNatMappingV4Config> = self.list().await?;
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
            .find_ids(device_ids.into_iter().collect())
            .await?;
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
        if !config.enable || config.mapping_pair_ports.is_empty() || config.l4_protocols.is_empty()
        {
            return Ok(false);
        }
        for (_, nat_config) in self.enabled_link_nats().await.map_err(StaticNatError::Internal)? {
            for proto in &config.l4_protocols {
                let range = match *proto {
                    6 => &nat_config.tcp_range,
                    17 => &nat_config.udp_range,
                    _ => continue,
                };
                if config
                    .mapping_pair_ports
                    .iter()
                    .any(|pair| pair.wan_port >= range.start && pair.wan_port <= range.end)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Effective dynamic NAT config (`None` ranges filled with the runtime
    /// defaults) of every `nat.enable` wan link, paired with the link's
    /// section iface name.
    pub async fn enabled_link_nats(&self) -> Result<Vec<(String, NatConfig)>, DbError> {
        Ok(WanLinkRepository::new(self.db.clone())
            .list()
            .await?
            .into_iter()
            .filter(|link| link.nat.enable)
            .map(|link| {
                let nat = RuntimeWanLinkConfig::from_config(&link).nat;
                (
                    link.section_iface_name().to_string(),
                    NatConfig {
                        tcp_range: nat.tcp_range,
                        udp_range: nat.udp_range,
                        icmp_in_range: nat.icmp_in_range,
                    },
                )
            })
            .collect())
    }

    async fn validate_no_static_port_overlap(
        &self,
        config: &StaticNatMappingV4Config,
    ) -> Result<(), ServiceConfigError> {
        let others = self.list().await.map_err(ServiceConfigError::internal)?;
        for other in others.iter().filter(|m| m.enable && m.id != config.id) {
            for proto in &config.l4_protocols {
                if !other.l4_protocols.contains(proto) {
                    continue;
                }
                let proto_name = if *proto == 6 { "TCP" } else { "UDP" };
                for pair in &config.mapping_pair_ports {
                    if other.mapping_pair_ports.iter().any(|p| p.wan_port == pair.wan_port) {
                        return Err(ServiceConfigError::InvalidConfig {
                            reason: format!(
                                "wan_port {} ({proto_name}) is already used by enabled static NAT mapping {}",
                                pair.wan_port, other.id
                            ),
                        });
                    }
                }
            }
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

#[async_trait::async_trait]
impl landscape_common::database::validator::StoreValidator<StaticNatMappingV4Config>
    for StaticNatMappingV4Repository
{
    async fn check_zone(
        &self,
        _config: &StaticNatMappingV4Config,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        Ok(())
    }

    async fn validate_cross(
        &self,
        config: &mut StaticNatMappingV4Config,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        crate::wan_link::repository::resolve_wan_link_binding(
            self.db.clone(),
            &mut config.wan_link_id,
            &mut config.wan_iface_name,
        )
        .await?;
        self.validate_runtime_target_v4(config).await.map_err(|e| {
            landscape_common::service::ServiceConfigError::InvalidConfig { reason: e.to_string() }
        })?;
        if !config.enable {
            return Ok(());
        }
        self.validate_no_static_port_overlap(config).await?;
        for (iface_name, nat_config) in
            self.enabled_link_nats().await.map_err(ServiceConfigError::internal)?
        {
            config.validate_no_dynamic_port_overlap(&nat_config).map_err(|e| match e {
                ServiceConfigError::InvalidConfig { reason } => ServiceConfigError::InvalidConfig {
                    reason: format!("{reason} (wan link {iface_name})"),
                },
                other => other,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use landscape_common::config_service::static_nat::config::StaticMapPair;
    use landscape_common::config_service::static_nat::config4::{
        StaticNatMappingV4Config, StaticNatV4Target,
    };
    use landscape_common::database::error::DbError;
    use landscape_common::database::store::ConfigStore;
    use landscape_common::service::ServiceConfigError;
    use landscape_common::wan_link::{WanLinkConfig, WanLinkKind, WanLinkNatConfig};
    use sea_orm::prelude::Uuid;

    use crate::provider::LandscapeDBServiceProvider;

    async fn insert_wan_nat_link(
        provider: &LandscapeDBServiceProvider,
        attach: &str,
        tcp_range: Option<(u16, u16)>,
        udp_range: Option<(u16, u16)>,
        nat_enable: bool,
    ) {
        provider
            .wan_link_store()
            .upsert(WanLinkConfig {
                id: Uuid::new_v4(),
                name: String::new(),
                attach_iface_name: attach.to_string(),
                kind: WanLinkKind::Ethernet,
                v4: Default::default(),
                pd: Default::default(),
                nat: WanLinkNatConfig {
                    enable: nat_enable,
                    tcp_range: tcp_range.map(|(start, end)| start..end),
                    udp_range: udp_range.map(|(start, end)| start..end),
                    icmp_in_range: None,
                },
                firewall: Default::default(),
                mss: Default::default(),
                update_at: 0.0,
            })
            .await
            .unwrap();
    }

    fn port_mapping(id: Uuid, enable: bool, wan_port: u16, proto: u8) -> StaticNatMappingV4Config {
        StaticNatMappingV4Config {
            id,
            name: None,
            enable,
            remark: String::new(),
            wan_link_id: None,
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(std::net::Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![proto],
            update_at: 0.0,
        }
    }

    fn new_port_mapping(enable: bool, wan_port: u16, proto: u8) -> StaticNatMappingV4Config {
        port_mapping(Uuid::new_v4(), enable, wan_port, proto)
    }

    fn expect_invalid_config<T: std::fmt::Debug>(result: Result<T, DbError>) -> String {
        match result {
            Err(DbError::Validation(ServiceConfigError::InvalidConfig { reason })) => reason,
            other => panic!("expected invalid config error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn conflict_when_wan_port_inside_dynamic_range() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((32768, 65535)), true)
            .await;

        let result = provider
            .static_nat_mapping_v4_store()
            .has_dynamic_port_conflict(&new_port_mapping(true, 40000, 6))
            .await
            .unwrap();
        assert!(result, "TCP port 40000 should conflict with range 32768-65535");
    }

    #[tokio::test]
    async fn no_conflict_when_wan_port_outside_dynamic_range() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((32768, 65535)), true)
            .await;

        let result = provider
            .static_nat_mapping_v4_store()
            .has_dynamic_port_conflict(&new_port_mapping(true, 80, 6))
            .await
            .unwrap();
        assert!(!result, "TCP port 80 should not conflict with range 32768-65535");
    }

    #[tokio::test]
    async fn no_conflict_when_link_nat_disabled() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((32768, 65535)), false)
            .await;

        let result = provider
            .static_nat_mapping_v4_store()
            .has_dynamic_port_conflict(&new_port_mapping(true, 40000, 6))
            .await
            .unwrap();
        assert!(!result, "disabled NAT should not cause conflict");
    }

    #[tokio::test]
    async fn default_dynamic_range_used_when_range_is_none() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", None, None, true).await;

        let repo = provider.static_nat_mapping_v4_store();
        assert!(repo.has_dynamic_port_conflict(&new_port_mapping(true, 40000, 6)).await.unwrap());
        assert!(!repo.has_dynamic_port_conflict(&new_port_mapping(true, 80, 6)).await.unwrap());
    }

    #[tokio::test]
    async fn conflict_matches_correct_protocol_range() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((10000, 20000)), true)
            .await;

        let result = provider
            .static_nat_mapping_v4_store()
            .has_dynamic_port_conflict(&new_port_mapping(true, 15000, 17))
            .await
            .unwrap();
        assert!(result, "UDP port 15000 should conflict with UDP range 10000-20000");
    }

    #[tokio::test]
    async fn no_conflict_when_protocol_range_mismatch() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((10000, 20000)), true)
            .await;

        let result = provider
            .static_nat_mapping_v4_store()
            .has_dynamic_port_conflict(&new_port_mapping(true, 40000, 17))
            .await
            .unwrap();
        assert!(!result, "UDP port 40000 should not conflict with UDP range 10000-20000");
    }

    #[tokio::test]
    async fn boundary_port_triggers_conflict() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((32768, 65535)), true)
            .await;

        let result = provider
            .static_nat_mapping_v4_store()
            .has_dynamic_port_conflict(&new_port_mapping(true, 32768, 6))
            .await
            .unwrap();
        assert!(result, "port at range start should be detected");
    }

    #[tokio::test]
    async fn checked_upsert_rejects_port_inside_enabled_link_range() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((32768, 65535)), true)
            .await;

        let result = provider
            .static_nat_mapping_v4_store()
            .checked_upsert(new_port_mapping(true, 40000, 6))
            .await;
        let reason = expect_invalid_config(result);
        assert!(
            reason.contains("wan link wan0"),
            "reason should name the conflicting link: {reason}"
        );
    }

    #[tokio::test]
    async fn checked_upsert_allows_port_when_link_nat_disabled() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((32768, 65535)), false)
            .await;

        provider
            .static_nat_mapping_v4_store()
            .checked_upsert(new_port_mapping(true, 40000, 6))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn disabled_mapping_skips_conflict_checks() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        insert_wan_nat_link(&provider, "wan0", Some((32768, 65535)), Some((32768, 65535)), true)
            .await;

        provider
            .static_nat_mapping_v4_store()
            .checked_upsert(new_port_mapping(false, 40000, 6))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn duplicate_wan_port_with_enabled_mapping_rejected() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let repo = provider.static_nat_mapping_v4_store();
        repo.upsert(new_port_mapping(true, 8080, 6)).await.unwrap();

        let reason =
            expect_invalid_config(repo.checked_upsert(new_port_mapping(true, 8080, 6)).await);
        assert!(reason.contains("already used"), "{reason}");
    }

    #[tokio::test]
    async fn duplicate_wan_port_with_other_protocol_allowed() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let repo = provider.static_nat_mapping_v4_store();
        repo.upsert(new_port_mapping(true, 8080, 6)).await.unwrap();

        repo.checked_upsert(new_port_mapping(true, 8080, 17)).await.unwrap();
    }

    #[tokio::test]
    async fn duplicate_wan_port_with_disabled_mapping_allowed() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let repo = provider.static_nat_mapping_v4_store();
        repo.upsert(new_port_mapping(false, 8080, 6)).await.unwrap();

        repo.checked_upsert(new_port_mapping(true, 8080, 6)).await.unwrap();
    }

    #[tokio::test]
    async fn mapping_update_keeps_own_port() {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let repo = provider.static_nat_mapping_v4_store();
        let id = Uuid::new_v4();
        repo.upsert(port_mapping(id, true, 8080, 6)).await.unwrap();

        let mut stored = repo.find_by_id(id).await.unwrap().unwrap();
        stored.remark = "updated".to_string();
        repo.checked_upsert(stored).await.unwrap();
    }

    fn mapping(
        wan_link_id: Option<Uuid>,
        wan_iface_name: Option<&str>,
    ) -> StaticNatMappingV4Config {
        StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            name: None,
            enable: true,
            remark: String::new(),
            wan_link_id,
            wan_iface_name: wan_iface_name.map(str::to_string),
            mapping_pair_ports: vec![StaticMapPair { wan_port: 80, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::Local),
            l4_protocols: vec![6],
            update_at: 0.0,
        }
    }

    async fn wan_link_setup() -> (LandscapeDBServiceProvider, Uuid) {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        let id = Uuid::new_v4();
        provider
            .wan_link_store()
            .upsert(landscape_common::wan_link::WanLinkConfig {
                id,
                name: String::new(),
                attach_iface_name: "eth0".to_string(),
                kind: landscape_common::wan_link::WanLinkKind::Ethernet,
                v4: Default::default(),
                pd: Default::default(),
                nat: Default::default(),
                firewall: Default::default(),
                mss: Default::default(),
                update_at: 0.0,
            })
            .await
            .unwrap();
        (provider, id)
    }

    #[tokio::test]
    async fn wan_binding_mirror_is_rewritten_from_the_link() {
        let (provider, link_id) = wan_link_setup().await;

        let saved = provider
            .static_nat_mapping_v4_store()
            .checked_upsert(mapping(Some(link_id), Some("stale")))
            .await
            .unwrap()
            .new;
        assert_eq!(saved.wan_iface_name.as_deref(), Some("eth0"));
    }

    #[tokio::test]
    async fn unbound_mapping_clears_the_wan_mirror() {
        let (provider, _) = wan_link_setup().await;

        let saved = provider
            .static_nat_mapping_v4_store()
            .checked_upsert(mapping(None, Some("eth0")))
            .await
            .unwrap()
            .new;
        assert_eq!(saved.wan_iface_name, None);
    }

    #[tokio::test]
    async fn unknown_wan_link_binding_is_rejected() {
        let (provider, _) = wan_link_setup().await;

        let result = provider
            .static_nat_mapping_v4_store()
            .checked_upsert(mapping(Some(Uuid::new_v4()), Some("eth0")))
            .await;
        assert!(result.is_err(), "an unknown wan_link_id must be rejected");
    }
}
