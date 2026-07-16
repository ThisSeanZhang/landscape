use serde::{Deserialize, Serialize};

use crate::cert::account::CertAccountConfig;
use crate::cert::order::CertConfig;
use crate::config::settings::LandscapeConfig;
use crate::config_service::enrolled_device::EnrolledDevice;
use crate::config_service::geo::{GeoIpSourceConfig, GeoSiteSourceConfig};
use crate::config_service::iface::NetworkIfaceConfig;
use crate::config_service::static_nat::config4::StaticNatMappingV4Config;
use crate::config_service::static_nat::config6::StaticNatMappingV6Config;
use crate::ddns::DdnsJob;
use crate::dns::config::DnsUpstreamConfig;
use crate::dns::provider_profile::DnsProviderProfile;
use crate::dns::redirect::DNSRedirectRule;
use crate::dns::rule::DNSRuleConfig;
use crate::flow::config::FlowConfig;
use crate::flow::ip_mark::WanIpRuleConfig;
use crate::flow::service::FlowWanServiceConfig;
use crate::lan_service::ap::WifiServiceConfig;
use crate::lan_service::lan_dhcpv4::config::DHCPv4ServiceConfig;
use crate::lan_service::lan_ipv6::LanIPv6ServiceConfigV2;
use crate::lan_service::lan_route::RouteLanServiceConfig;
use crate::sys_service::gateway::HttpUpstreamRuleConfig;
use crate::wan_service::firewall::blacklist::FirewallBlacklistConfig;
use crate::wan_service::firewall::service::FirewallServiceConfig;
use crate::wan_service::firewall::FirewallRuleConfig;
use crate::wan_service::ip_config::IfaceIpServiceConfig;
use crate::wan_service::ipv6_pd::IPV6PDServiceConfig;
use crate::wan_service::mss_clamp::MSSClampServiceConfig;
use crate::wan_service::nat::config::NatServiceConfig;
use crate::wan_service::pppd::PPPDServiceConfig;
use crate::wan_service::wan_route::RouteWanServiceConfig;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(default)]
pub struct InitConfig {
    pub version: String,
    pub config: LandscapeConfig,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ifaces: Vec<NetworkIfaceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ipconfigs: Vec<IfaceIpServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nats: Vec<NatServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub marks: Vec<FlowWanServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pppds: Vec<PPPDServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flow_rules: Vec<FlowConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_rules: Vec<DNSRuleConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dst_ip_mark: Vec<WanIpRuleConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dhcpv6pds: Vec<IPV6PDServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub lan_ipv6s: Vec<LanIPv6ServiceConfigV2>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub firewalls: Vec<FirewallServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub firewall_rules: Vec<FirewallRuleConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub firewall_blacklists: Vec<FirewallBlacklistConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub wifi_configs: Vec<WifiServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dhcpv4_services: Vec<DHCPv4ServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mss_clamps: Vec<MSSClampServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub geo_ips: Vec<GeoIpSourceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub geo_sites: Vec<GeoSiteSourceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub route_lans: Vec<RouteLanServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub route_wans: Vec<RouteWanServiceConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub static_nat_mappings_v4: Vec<StaticNatMappingV4Config>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub static_nat_mappings_v6: Vec<StaticNatMappingV6Config>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_redirects: Vec<DNSRedirectRule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_upstream_configs: Vec<DnsUpstreamConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub enrolled_devices: Vec<EnrolledDevice>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub cert_accounts: Vec<CertAccountConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certs: Vec<CertConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gateway_rules: Vec<HttpUpstreamRuleConfig>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ddns_jobs: Vec<DdnsJob>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns_provider_profiles: Vec<DnsProviderProfile>,
}

#[cfg(test)]
mod tests {
    use super::InitConfig;
    use crate::VERSION;

    #[test]
    fn deserialize_init_config_version() {
        let config: InitConfig = toml::from_str(&format!(
            r#"
                version = "{VERSION}"
            "#
        ))
        .unwrap();

        assert_eq!(config.version, VERSION);
    }

    #[test]
    fn deserialize_legacy_init_config_defaults_empty_version() {
        let config: InitConfig = toml::from_str("").unwrap();

        assert_eq!(config.version, "");
    }

    #[test]
    fn deserialize_v2_lan_ipv6s_without_conversion() {
        let config: InitConfig = toml::from_str(
            r#"
                [[lan_ipv6s]]
                iface_name = "lan0"
                enable = true
                update_at = 0.0

                [lan_ipv6s.config]
                mode = "slaac"
                ad_interval = 300

                [lan_ipv6s.config.ra_flag]
                managed_address_config = false
                other_config = false
                home_agent = false
                prf = 0
                nd_proxy = false
                reserved = 0

                [[lan_ipv6s.config.prefix_groups]]
                group_id = "static:fd00::/60"

                [lan_ipv6s.config.prefix_groups.parent]
                t = "static"
                base_prefix = "fd00::"
                parent_prefix_len = 60

                [lan_ipv6s.config.prefix_groups.ra]
                pool_index = 1
                preferred_lifetime = 300
                valid_lifetime = 600
            "#,
        )
        .unwrap();

        assert_eq!(config.lan_ipv6s.len(), 1);
        assert_eq!(config.lan_ipv6s[0].config.prefix_groups.len(), 1);
        assert_eq!(config.lan_ipv6s[0].config.prefix_groups[0].group_id, "static:fd00::/60");
    }
}
