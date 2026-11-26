use landscape::config_service::gateway_rule_service::GatewayRuleConfigService;
use std::{path::PathBuf, sync::Arc};

use self::system_config::SystemConfigEditor;
use axum::extract::FromRef;
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_core::time::SyncTimeService;
use landscape_ebpf::maps::LandscapeMapPath;

use landscape::{
    cert::{account_service::CertAccountService, order_service::CertService},
    config_service::enrolled_device_service::EnrolledDeviceService,
    config_service::firewall_blacklist_service::FirewallBlacklistService,
    config_service::iface_service::IfaceManagerService,
    config_service::static_nat4_mapping_service::StaticNat4MappingService,
    config_service::static_nat6_mapping_service::StaticNat6MappingService,
    ddns::DdnsService,
    dns::{
        provider_profile_service::DnsProviderProfileService, redirect_service::DNSRedirectService,
        rule_service::DNSRuleService, upstream_service::DnsUpstreamService,
    },
    docker::LandscapeDockerService,
    flow::{dst_ip_rule_service::DstIpRuleService, rule_service::FlowRuleService},
    geo::{ip_service::GeoIpService, site_service::GeoSiteService},
    lan_service::lan_dhcp4_service::DHCPv4ServerManagerService,
    lan_service::lan_ipv6_service::LanIPv6ManagerService,
    lan_service::lan_route_service::RouteLanServiceManagerService,
    metric::MetricService,
    sys_service::gateway::GatewayService,
    sys_service::route::IpRouteService,
    sys_service::{
        config_service::LandscapeConfigService, dns_service::LandscapeDnsService,
        ebpf_service::LandscapeEbpfService,
    },
    wan_link_service::WanLinkServiceManagerService,
    wan_service::wan_route_service::RouteWanServiceManagerService,
    wifi::WifiServiceManagerService,
};

mod iface_lifecycle;
mod shutdown;
pub(crate) mod system_config;

#[derive(Clone)]
pub struct LandscapeApp {
    pub(crate) home_path: PathBuf,

    // Runtime singletons (not backed by the config store).
    /// eBPF map pin paths (for ad-hoc map introspection endpoints).
    pub(crate) ebpf_paths: Arc<LandscapeMapPath>,
    pub(crate) route_service: IpRouteService,
    /// LAN device directory: authoritative runtime view of LAN devices
    /// (identity + addresses) for API point reads.
    pub(crate) lan_device_directory: Arc<LanDeviceDirectory>,
    pub(crate) docker_service: LandscapeDockerService,
    pub(crate) ebpf_service: LandscapeEbpfService,

    /// toml 配置驱动的系统级单例服务。
    pub(crate) system: SystemServices,

    /// ConfigStore 驱动的配置服务。
    pub(crate) managed: ManagedServices,
}

#[derive(Clone)]
pub(crate) struct SystemServices {
    settings: SystemConfigEditor,
    pub dns_service: LandscapeDnsService,
    /// Metric
    pub metric_service: MetricService,
}

impl SystemServices {
    pub(crate) fn new(
        config: LandscapeConfigService,
        dns_service: LandscapeDnsService,
        time_service: SyncTimeService,
        metric_service: MetricService,
    ) -> Self {
        Self {
            settings: SystemConfigEditor::new(config, time_service),
            dns_service,
            metric_service,
        }
    }
    pub(crate) fn time_service(&self) -> &SyncTimeService {
        &self.settings.time
    }
}

// All online TOML editors share the same commit lock and runtime publishers.
impl FromRef<LandscapeApp> for LandscapeConfigService {
    fn from_ref(app: &LandscapeApp) -> Self {
        Self::from_ref(&app.system.settings)
    }
}

#[derive(Clone)]
pub(crate) struct ManagedServices {
    pub dns_provider_profile_service: DnsProviderProfileService,
    pub dns_rule_service: DNSRuleService,
    pub dns_redirect_service: DNSRedirectService,
    pub dns_upstream_service: DnsUpstreamService,
    pub ddns_service: DdnsService,
    pub flow_rule_service: FlowRuleService,
    pub dst_ip_rule_service: DstIpRuleService,
    pub geo_site_service: GeoSiteService,
    pub geo_ip_service: GeoIpService,
    pub firewall_blacklist_service: FirewallBlacklistService,

    pub dhcp_v4_server_service: DHCPv4ServerManagerService,
    pub route_lan_service: RouteLanServiceManagerService,
    pub route_wan_service: RouteWanServiceManagerService,
    /// Iface Config
    pub iface_config_service: IfaceManagerService,
    /// WAN Link Service: owns the per-link WAN service set (v4 / nat / mss /
    /// firewall / pd) that replaced the per-iface service managers.
    pub wan_link_service: WanLinkServiceManagerService,
    /// ipv6
    pub lan_ipv6_service: LanIPv6ManagerService,
    // Static NAT Mapping
    pub static_nat4_mapping_service: StaticNat4MappingService,
    pub static_nat6_mapping_service: StaticNat6MappingService,
    pub wifi_service: WifiServiceManagerService,

    pub enrolled_device_service: EnrolledDeviceService,
    pub cert_account_service: CertAccountService,
    pub cert_service: CertService,

    // Gateway
    pub gateway_rules: GatewayRuleConfigService,
    pub gateway_service: GatewayService,
}
