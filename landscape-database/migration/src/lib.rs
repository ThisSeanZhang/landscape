pub use sea_orm_migration::prelude::*;

mod m20250511_170500_dns_rule;
mod m20250517_083437_iface_config;
mod m20250518_081203_dhcp_v4_server;
mod m20250519_004726_dhcp_v6_client;
mod m20250519_070236_firewall;
mod m20250519_074411_flow_wan;
mod m20250519_081012_mss_clamp;
mod m20250519_083637_nat_service;
mod m20250519_094250_pppd;
mod m20250519_125555_ipv6_ra;
mod m20250520_013248_iface_ip;
mod m20250520_055039_wifi;
mod m20250521_095934_firewall_rule;
mod m20250521_130018_flow_rule;
mod m20250521_150250_dst_ip_rule;
mod m20250525_030646_geo_site;
mod m20250530_142817_geo_ip;
mod m20250706_165958_route_lan;
mod m20250706_170000_route_wan;
mod m20250814_084024_static_nat_mapping;
mod m20250901_031230_dns_redirect;
mod m20250903_112656_dns_upstream;
mod m20251003_123332_add_mac_match_in_flow;
mod m20251009_051553_multiple_ra;
mod m20251013_144933_add_ip_validation_to_dns_upstream;
mod m20251025_064017_add_ac_in_pppd;
mod m20251216_141215_lan_static_route;
mod m20260122_125946_multiple_nat_ports;
mod m20260124_140950_dns_bind_addr;
mod m20260126_111753_ip_mac_binding;
mod tables;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250511_170500_dns_rule::Migration),
            Box::new(m20250517_083437_iface_config::Migration),
            Box::new(m20250518_081203_dhcp_v4_server::Migration),
            Box::new(m20250519_004726_dhcp_v6_client::Migration),
            Box::new(m20250519_070236_firewall::Migration),
            Box::new(m20250519_074411_flow_wan::Migration),
            Box::new(m20250519_081012_mss_clamp::Migration),
            Box::new(m20250519_083637_nat_service::Migration),
            Box::new(m20250519_094250_pppd::Migration),
            Box::new(m20250519_125555_ipv6_ra::Migration),
            Box::new(m20250520_013248_iface_ip::Migration),
            Box::new(m20250520_055039_wifi::Migration),
            Box::new(m20250521_095934_firewall_rule::Migration),
            Box::new(m20250521_130018_flow_rule::Migration),
            Box::new(m20250521_150250_dst_ip_rule::Migration),
            Box::new(m20250525_030646_geo_site::Migration),
            Box::new(m20250530_142817_geo_ip::Migration),
            Box::new(m20250706_165958_route_lan::Migration),
            Box::new(m20250706_170000_route_wan::Migration),
            Box::new(m20250814_084024_static_nat_mapping::Migration),
            Box::new(m20250901_031230_dns_redirect::Migration),
            Box::new(m20250903_112656_dns_upstream::Migration),
            Box::new(m20251003_123332_add_mac_match_in_flow::Migration),
            Box::new(m20251009_051553_multiple_ra::Migration),
            Box::new(m20251013_144933_add_ip_validation_to_dns_upstream::Migration),
            Box::new(m20251025_064017_add_ac_in_pppd::Migration),
            Box::new(m20251216_141215_lan_static_route::Migration),
            Box::new(m20260122_125946_multiple_nat_ports::Migration),
            Box::new(m20260124_140950_dns_bind_addr::Migration),
            Box::new(m20260126_111753_ip_mac_binding::Migration),
        ]
    }
}
