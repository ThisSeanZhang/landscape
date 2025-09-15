use std::time::Duration;

use landscape_common::{
    config::{InitConfig, StoreRuntimeConfig},
    database::repository::Repository,
};
use sea_orm::{Database, DatabaseConnection};

use migration::{Migrator, MigratorTrait};

use crate::{
    dhcp_v4_server::repository::DHCPv4ServerRepository,
    dhcp_v6_client::repository::DHCPv6ClientRepository,
    dns_redirect::repository::DNSRedirectRuleRepository, dns_rule::repository::DNSRuleRepository,
    dns_upstream::repository::DnsUpstreamRepository, dst_ip_rule::repository::DstIpRuleRepository,
    firewall::repository::FirewallServiceRepository,
    firewall_rule::repository::FirewallRuleRepository, flow_rule::repository::FlowConfigRepository,
    flow_wan::repository::FlowWanServiceRepository,
    geo_ip::repository::GeoIpSourceConfigRepository, geo_site::repository::GeoSiteConfigRepository,
    iface::repository::NetIfaceRepository, iface_ip::repository::IfaceIpServiceRepository,
    mss_clamp::repository::MssClampServiceRepository, nat::repository::NatServiceRepository,
    pppd::repository::PPPDServiceRepository, ra::repository::IPV6RAServiceRepository,
    route_lan::repository::RouteLanServiceRepository,
    route_wan::repository::RouteWanServiceRepository,
    static_nat_mapping::repository::StaticNatMappingConfigRepository,
    wifi::repository::WifiServiceRepository,
};

pub async fn db_action(config: &StoreRuntimeConfig, rollback: &bool, steps: &u32) {
    let opt: migration::sea_orm::ConnectOptions = config.database_path.clone().into();
    let database = Database::connect(opt).await.expect("Database connection failed");

    if *rollback {
        Migrator::down(&database, Some(*steps)).await.unwrap();
    } else {
        Migrator::up(&database, Some(*steps)).await.unwrap();
    }
}

/// 存储提供者  
/// 后续有需要再进行抽象
#[derive(Clone)]
pub struct LandscapeDBServiceProvider {
    database: DatabaseConnection,
}

impl LandscapeDBServiceProvider {
    pub async fn new(config: &StoreRuntimeConfig) -> Self {
        let mut opt: migration::sea_orm::ConnectOptions = config.database_path.clone().into();
        let (lever, _) = opt.get_sqlx_slow_statements_logging_settings();
        opt.sqlx_slow_statements_logging_settings(lever, Duration::from_secs(10));

        let database = Database::connect(opt).await.expect("Database connection failed");
        Migrator::up(&database, None).await.unwrap();
        Self { database }
    }

    pub async fn mem_test_db() -> Self {
        let database =
            Database::connect("sqlite::memory:").await.expect("Database connection failed");
        Migrator::up(&database, None).await.unwrap();
        Self { database }
    }
}

macro_rules! define_store {
    ( $( $store_name:ident : ($repo_type:ty, $init_field:ident) ),* $(,)? ) => {
        impl LandscapeDBServiceProvider {
            $(
                // 生成 getter
                pub fn $store_name(&self) -> $repo_type {
                    <$repo_type>::new(self.database.clone())
                }
            )*

            pub async fn truncate_and_fit_from(&self, config: Option<InitConfig>) {
                if let Some(cfg) = config {
                    $(
                        let store = self.$store_name();
                        store.truncate_table().await.unwrap();
                        for each_config in cfg.$init_field {
                            store.set_model(each_config).await.unwrap();
                        }
                    )*
                }
            }
        }
    }
}

define_store!(
    iface_store: (NetIfaceRepository, ifaces),
    dhcp_v4_server_store: (DHCPv4ServerRepository, dhcpv4_services),
    wifi_service_store: (WifiServiceRepository, wifi_configs),
    firewall_service_store: (FirewallServiceRepository, firewalls),
    firewall_rule_store: (FirewallRuleRepository, firewall_rules),
    iface_ip_service_store: (IfaceIpServiceRepository, ipconfigs),
    nat_service_store: (NatServiceRepository, nats),
    flow_rule_store: (FlowConfigRepository, flow_rules),
    flow_wan_service_store: (FlowWanServiceRepository, marks),
    dst_ip_rule_store: (DstIpRuleRepository, dst_ip_mark),
    pppd_service_store: (PPPDServiceRepository, pppds),
    dns_rule_store: (DNSRuleRepository, dns_rules),
    dhcp_v6_client_store: (DHCPv6ClientRepository, dhcpv6pds),
    ra_service_store: (IPV6RAServiceRepository, icmpras),
    mss_clamp_service_store: (MssClampServiceRepository, mss_clamps),
    geo_ip_rule_store: (GeoIpSourceConfigRepository, geo_ips),
    geo_site_rule_store: (GeoSiteConfigRepository, geo_sites),
    route_lan_service_store: (RouteLanServiceRepository, route_lans),
    route_wan_service_store: (RouteWanServiceRepository, route_wans),
    static_nat_mapping_store: (StaticNatMappingConfigRepository, static_nat_mappings),
    dns_redirect_rule_store: (DNSRedirectRuleRepository, dns_redirects),
    dns_upstream_config_store: (DnsUpstreamRepository, dns_upstream_configs),
);

#[cfg(test)]
mod tests {
    use landscape_common::config::StoreRuntimeConfig;

    use crate::provider::LandscapeDBServiceProvider;

    #[tokio::test]
    pub async fn test_run_database() {
        landscape_common::init_tracing!();

        let config = StoreRuntimeConfig {
            database_path: "sqlite://../db.sqlite?mode=rwc".to_string(),
        };
        let _provider = LandscapeDBServiceProvider::new(&config).await;
    }
}
