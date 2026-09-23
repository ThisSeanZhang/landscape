use std::net::Ipv4Addr;
use std::sync::Arc;

use landscape_common::config_service::static_nat::config::StaticMapPair;
use landscape_common::config_service::static_nat::config4::{
    StaticNatMappingV4Config, StaticNatV4Target,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::database::error::DbError;
use landscape_common::database::LandscapeStore;
use landscape_common::event::hub::EnrolledDeviceEventReader;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_common::LANDSCAPE_DEFAULE_DHCP_V4_CLIENT_PORT;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::static_nat_mapping_v4::repository::StaticNatMappingV4Repository;
use landscape_database::wan_link::repository::WanLinkRepository;
use uuid::Uuid;

use crate::wan_service::link_service::resolve::resolve_nat;

#[derive(Clone)]
pub struct StaticNat4MappingService {
    store: StaticNatMappingV4Repository,
    wan_link_store: WanLinkRepository,
    dataplane: Arc<dyn NatDataplane>,
}

impl StaticNat4MappingService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        device_reader: EnrolledDeviceEventReader,
        dataplane: Arc<dyn NatDataplane>,
    ) -> Self {
        let service = Self {
            store: store_provider.static_nat_mapping_v4_store(),
            wan_link_store: store_provider.wan_link_store(),
            dataplane,
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
    ) -> Result<StaticNatMappingV4Config, DbError> {
        let result = self.store.checked_set(config).await?;
        self.refresh_runtime_rules().await;
        Ok(result)
    }

    pub async fn checked_set_list(
        &self,
        configs: Vec<StaticNatMappingV4Config>,
    ) -> Result<(), DbError> {
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

    /// All enabled dynamic NAT ranges, keyed by the link's runtime iface name.
    /// The authoritative source is `wan_links.nat`, not the legacy NAT store.
    async fn dynamic_nat_ranges(&self) -> Vec<(String, NatConfig)> {
        self.wan_link_store
            .list()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|link| link.nat.enable)
            .map(|link| (link.net_iface_name(), resolve_nat(&link.nat)))
            .collect()
    }

    pub async fn check_port_conflict(
        &self,
        wan_port: u16,
        protocols: &[u8],
    ) -> Result<Option<StaticNatError>, DbError> {
        for (iface_name, nat_config) in self.dynamic_nat_ranges().await {
            for proto in protocols {
                let range = match *proto {
                    6 => &nat_config.tcp_range,
                    17 => &nat_config.udp_range,
                    _ => continue,
                };
                if wan_port >= range.start && wan_port <= range.end {
                    return Ok(Some(StaticNatError::PortConflict {
                        port: wan_port,
                        iface_name,
                        protocol: *proto,
                        start: range.start,
                        end: range.end,
                    }));
                }
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
        for (iface_name, nat_config) in self.dynamic_nat_ranges().await {
            for proto in &config.l4_protocols {
                let range = match *proto {
                    6 => &nat_config.tcp_range,
                    17 => &nat_config.udp_range,
                    _ => continue,
                };
                for pair in &config.mapping_pair_ports {
                    if pair.wan_port >= range.start && pair.wan_port <= range.end {
                        return Err(StaticNatError::PortConflict {
                            port: pair.wan_port,
                            iface_name,
                            protocol: *proto,
                            start: range.start,
                            end: range.end,
                        });
                    }
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

        self.dataplane.sync_static_nat4(&configs);
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

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use landscape_common::database::LandscapeStore;
    use landscape_common::wan_service::link::{WanLinkConfig, WanNatConfig};
    use landscape_common::wan_service::nat::dataplane::NoopNatDataplane;

    use super::*;

    fn nat_link(
        iface: &str,
        enable: bool,
        tcp: Option<Range<u16>>,
        udp: Option<Range<u16>>,
    ) -> WanLinkConfig {
        WanLinkConfig {
            attach_iface_name: iface.to_string(),
            nat: WanNatConfig {
                enable,
                tcp_range: tcp,
                udp_range: udp,
                icmp_in_range: None,
            },
            ..Default::default()
        }
    }

    async fn service_with_links(links: Vec<WanLinkConfig>) -> StaticNat4MappingService {
        let provider = LandscapeDBServiceProvider::mem_test_db().await;
        for link in links {
            provider.wan_link_store().set(link).await.unwrap();
        }

        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        StaticNat4MappingService::new(
            provider,
            EnrolledDeviceEventReader::new(rx),
            Arc::new(NoopNatDataplane),
        )
        .await
    }

    async fn service_with_nat(
        tcp: Option<Range<u16>>,
        udp: Option<Range<u16>>,
    ) -> StaticNat4MappingService {
        service_with_links(vec![nat_link("wan0", true, tcp, udp)]).await
    }

    fn mapping(wan_port: u16, proto: u8) -> StaticNatMappingV4Config {
        StaticNatMappingV4Config {
            id: Uuid::new_v4(),
            enable: true,
            remark: String::new(),
            wan_iface_name: None,
            mapping_pair_ports: vec![StaticMapPair { wan_port, lan_port: 80 }],
            lan_target: Some(StaticNatV4Target::address(Ipv4Addr::new(192, 168, 1, 100))),
            l4_protocols: vec![proto],
            update_at: 0.0,
        }
    }

    #[tokio::test]
    async fn check_port_conflict_reads_link_nat_ranges() {
        let service = service_with_nat(Some(32768..65535), Some(10000..20000)).await;

        assert!(service.check_port_conflict(40000, &[6]).await.unwrap().is_some());
        assert!(service.check_port_conflict(15000, &[17]).await.unwrap().is_some());
        assert!(service.check_port_conflict(80, &[6]).await.unwrap().is_none());
        // Protocol/range mismatch must not be reported as a conflict.
        assert!(service.check_port_conflict(40000, &[17]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn validate_no_dynamic_port_conflict_reads_link_nat_ranges() {
        let service = service_with_nat(Some(32768..65535), Some(32768..65535)).await;

        assert!(service.validate_no_dynamic_port_conflict(&mapping(40000, 6)).await.is_err());
        assert!(service.validate_no_dynamic_port_conflict(&mapping(80, 6)).await.is_ok());
    }

    #[tokio::test]
    async fn unset_ranges_fall_back_to_nat_defaults() {
        // `WanNatConfig` with no ranges resolves to `NatConfig::default()`
        // (32768..65535), so the check must still fire.
        let service = service_with_nat(None, None).await;

        assert!(service.check_port_conflict(40000, &[6]).await.unwrap().is_some());
        assert!(service.check_port_conflict(80, &[6]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn conflict_is_aggregated_across_links() {
        let service = service_with_links(vec![
            nat_link("wan0", false, Some(1000..2000), Some(1000..2000)),
            nat_link("wan1", true, Some(32768..65535), None),
        ])
        .await;

        // The conflict comes from the second (enabled) link; the disabled
        // first link must be ignored.
        assert!(service.check_port_conflict(40000, &[6]).await.unwrap().is_some());
        assert!(service.check_port_conflict(1500, &[6]).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn disabled_link_nat_is_ignored() {
        let service =
            service_with_links(vec![nat_link("wan0", false, Some(32768..65535), None)]).await;

        assert!(service.check_port_conflict(40000, &[6]).await.unwrap().is_none());
    }
}
