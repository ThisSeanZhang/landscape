use landscape_common::config::{InitConfig, RuntimeConfig};
use landscape_common::database::LandscapeDBTrait;
use landscape_database::provider::LandscapeDBServiceProvider;

#[derive(Clone)]
pub struct LandscapeConfigService {
    config: RuntimeConfig,
    store: LandscapeDBServiceProvider,
}

impl LandscapeConfigService {
    pub async fn new(config: RuntimeConfig, store: LandscapeDBServiceProvider) -> Self {
        LandscapeConfigService { config, store }
    }

    pub async fn export_init_config(&self) -> InitConfig {
        InitConfig {
            config: self.config.file_config.clone(),
            ifaces: self.store.iface_store().list().await.unwrap(),
            ipconfigs: self.store.iface_ip_service_store().list().await.unwrap(),
            nats: self.store.nat_service_store().list().await.unwrap(),
            marks: self.store.flow_wan_service_store().list().await.unwrap(),
            pppds: self.store.pppd_service_store().list().await.unwrap(),
            flow_rules: self.store.flow_rule_store().list().await.unwrap(),
            dns_rules: self.store.dns_rule_store().list().await.unwrap(),
            dst_ip_mark: self.store.dst_ip_rule_store().list().await.unwrap(),
            dhcpv6pds: self.store.dhcp_v6_client_store().list().await.unwrap(),
            icmpras: self.store.ra_service_store().list().await.unwrap(),
            firewalls: self.store.firewall_service_store().list().await.unwrap(),
            firewall_rules: self.store.firewall_rule_store().list().await.unwrap(),
            wifi_configs: self.store.wifi_service_store().list().await.unwrap(),
            dhcpv4_services: self.store.dhcp_v4_server_store().list().await.unwrap(),
            mss_clamps: self.store.mss_clamp_service_store().list().await.unwrap(),
            geo_ips: self.store.geo_ip_rule_store().list().await.unwrap(),
            geo_sites: self.store.geo_site_rule_store().list().await.unwrap(),
            route_lans: self.store.route_lan_service_store().list().await.unwrap(),
            route_wans: self.store.route_wan_service_store().list().await.unwrap(),
            static_nat_mappings: self.store.static_nat_mapping_store().list().await.unwrap(),
            dns_redirects: self.store.dns_redirect_rule_store().list().await.unwrap(),
            dns_upstream_configs: self.store.dns_upstream_config_store().list().await.unwrap(),
        }
    }
}
