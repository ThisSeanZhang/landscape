use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use landscape_ebpf::maps::LandscapeMapPath;

use landscape::{
    cert::{account_service::CertAccountService, order_service::CertService},
    config_service::enrolled_device_service::EnrolledDeviceService,
    config_service::firewall_blacklist_service::FirewallBlacklistService,
    config_service::iface_service::IfaceManagerService,
    config_service::static_nat4_mapping_service::StaticNat4MappingService,
    config_service::static_nat6_mapping_service::StaticNat6MappingService,
    dns::{
        ddns_service::DdnsService, provider_profile_service::DnsProviderProfileService,
        redirect_service::DNSRedirectService, rule_service::DNSRuleService,
        upstream_service::DnsUpstreamService,
    },
    docker::LandscapeDockerService,
    flow::{dst_ip_rule_service::DstIpRuleService, rule_service::FlowRuleService},
    geo::{ip_service::GeoIpService, site_service::GeoSiteService},
    lan_service::lan_dhcp4_service::DHCPv4ServerManagerService,
    lan_service::lan_ipv6_service::LanIPv6ManagerService,
    lan_service::lan_route_service::RouteLanServiceManagerService,
    metric::MetricService,
    sys_service::route::IpRouteService,
    sys_service::{
        config_service::LandscapeConfigService, dns_service::LandscapeDnsService,
        ebpf_service::LandscapeEbpfService,
    },
    wan_service::firewall::FirewallServiceManagerService,
    wan_service::{
        ipconfig_service::IfaceIpServiceManagerService, ipv6pd_service::DHCPv6ClientManagerService,
        mss_clamp_service::MssClampServiceManagerService, nat_service::NatServiceManagerService,
        pppd_service::PPPDServiceConfigManagerService,
        wan_route_service::RouteWanServiceManagerService,
    },
    wifi::WifiServiceManagerService,
};

use landscape_common::{
    config::AuthRuntimeConfig,
    memtrack::MemoryHistory,
    service::controller::{ConfigStoreController, ConfigStoreServiceController},
    wan_service::ip_config::IfaceIpModelConfig,
};
use landscape_core::time::SyncTimeService;

use crate::gateway_runtime::GatewayService;

#[allow(dead_code)]
#[derive(Clone)]
pub struct LandscapeApp {
    pub home_path: PathBuf,
    pub auth: Arc<ArcSwap<AuthRuntimeConfig>>,
    /// eBPF map pin paths (for ad-hoc map introspection endpoints).
    pub(crate) ebpf_paths: Arc<LandscapeMapPath>,
    pub dns_service: LandscapeDnsService,
    pub ddns_service: DdnsService,
    pub dns_provider_profile_service: DnsProviderProfileService,
    pub dns_rule_service: DNSRuleService,
    pub flow_rule_service: FlowRuleService,
    pub geo_site_service: GeoSiteService,
    pub firewall_blacklist_service: FirewallBlacklistService,
    pub dst_ip_rule_service: DstIpRuleService,
    pub geo_ip_service: GeoIpService,
    pub config_service: LandscapeConfigService,

    /// Time sync (NTP) service.
    pub(crate) time_service: SyncTimeService,

    pub dhcp_v4_server_service: DHCPv4ServerManagerService,

    /// Metric
    pub metric_service: MetricService,

    /// 进程内存快照环形缓冲(1s 采样,最近 1 小时),服务 /system/memory 实时查询。
    pub memory_history: MemoryHistory,

    /// Route
    pub route_service: IpRouteService,
    pub route_lan_service: RouteLanServiceManagerService,
    pub route_wan_service: RouteWanServiceManagerService,

    /// Iface Config
    pub(crate) iface_config_service: IfaceManagerService,
    /// Iface IP Service
    pub(crate) wan_ip_service: IfaceIpServiceManagerService,
    pub(crate) docker_service: LandscapeDockerService,

    /// pppd service
    pub(crate) pppd_service: PPPDServiceConfigManagerService,

    /// ipv6
    pub(crate) ipv6_pd_service: DHCPv6ClientManagerService,
    pub(crate) lan_ipv6_service: LanIPv6ManagerService,

    // Static NAT Mapping
    pub(crate) static_nat4_mapping_service: StaticNat4MappingService,
    pub(crate) static_nat6_mapping_service: StaticNat6MappingService,

    /// DNS Redirect Service
    pub(crate) dns_redirect_service: DNSRedirectService,

    pub(crate) dns_upstream_service: DnsUpstreamService,

    /// Mss Clamp Service
    pub(crate) mss_clamp_service: MssClampServiceManagerService,
    pub(crate) firewall_service: FirewallServiceManagerService,
    pub(crate) wifi_service: WifiServiceManagerService,
    pub(crate) nat_service: NatServiceManagerService,

    pub(crate) ebpf_service: LandscapeEbpfService,
    pub(crate) enrolled_device_service: EnrolledDeviceService,

    pub(crate) cert_account_service: CertAccountService,
    pub(crate) cert_service: CertService,

    // Gateway
    pub(crate) gateway_service: GatewayService,
}

impl LandscapeApp {
    pub(crate) async fn remove_direct_iface_service(&self, iface_name: &str) {
        if let Err(error) =
            self.mss_clamp_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!("failed to remove mss clamp service for {iface_name}: {error:?}");
        }
        if let Err(error) =
            self.wan_ip_service.delete_and_stop_iface_service(iface_name.to_string()).await
        {
            tracing::error!(%error, "deleting IP config service for '{iface_name}' failed");
        }
        if let Err(error) =
            self.firewall_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!("failed to remove firewall service for {iface_name}: {error:?}");
        }
        if let Err(error) =
            self.nat_service.delete_and_stop_iface_service(iface_name.to_string()).await
        {
            tracing::error!(%error, "deleting NAT service for '{iface_name}' failed");
        }
        if let Err(error) =
            self.ipv6_pd_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!("failed to remove IPv6PD service for {iface_name}: {error:?}");
        }
        if let Err(error) =
            self.route_wan_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!("failed to remove route wan service for {iface_name}: {error:?}");
        }
        if let Err(error) =
            self.dhcp_v4_server_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!(%error, "deleting DHCPv4 service for '{iface_name}' failed");
        }
        if let Err(error) =
            self.lan_ipv6_service.delete_and_stop_iface_service(iface_name.to_string()).await
        {
            tracing::error!(%error, "deleting LAN IPv6 service for '{iface_name}' failed");
        }
        if let Err(error) =
            self.route_lan_service.delete_and_stop_service(iface_name.to_string()).await
        {
            tracing::error!("failed to remove route lan service for {iface_name}: {error:?}");
        }
    }

    pub(crate) async fn remove_all_iface_service(&self, iface_name: &str) {
        self.remove_direct_iface_service(iface_name).await;
        crate::services::pppoe::delete_ppp_ifaces_by_attach_name(self, iface_name).await;
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down all services...");

        self.gateway_service.shutdown_and_wait(Duration::from_secs(10)).await;
        tracing::info!("Gateway service stopped");

        tokio::join!(
            self.mss_clamp_service.get_service().stop_all(),
            self.firewall_service.get_service().stop_all(),
            self.nat_service.get_service().stop_all(),
            self.route_wan_service.get_service().stop_all(),
            self.route_lan_service.get_service().stop_all(),
            self.dhcp_v4_server_service.get_service().stop_all(),
            self.ipv6_pd_service.get_service().stop_all(),
            self.lan_ipv6_service.get_service().stop_all(),
            self.wan_ip_service.get_service().stop_all(),
            self.pppd_service.get_service().stop_all(),
            self.wifi_service.get_service().stop_all(),
        );
        tracing::info!("All service managers stopped");

        landscape_ebpf::maps::cleanup_pinned_maps();

        self.metric_service.stop_service().await;
        tracing::info!("Metric service stopped");

        self.ebpf_service.stop().await;
        tracing::info!("eBPF system service stopped");

        self.dns_service.stop().await;
        tracing::info!("DNS resolver conf restored");

        self.preserve_critical_ips().await;
        tracing::info!("Critical IPs preserved");

        // Time sync keeps the clock sane for every other service, stop it last.
        self.time_service.stop().await;
        tracing::info!("Time sync service stopped");
    }

    async fn preserve_critical_ips(&self) {
        let dhcp_configs = self.dhcp_v4_server_service.list().await.unwrap_or_default();

        for config in &dhcp_configs {
            if config.enable {
                let ip = IpAddr::V4(config.config.server_ip_addr);
                let prefix_len = config.config.network_mask;
                tracing::info!(
                    "Re-applying DHCPv4 server IP: {ip}/{prefix_len} on {}",
                    config.iface_name
                );
                landscape::netlink::address::set_iface_ip(&config.iface_name, ip, prefix_len).await;
            }
        }

        let ip_configs = self.wan_ip_service.list().await.unwrap_or_default();

        for config in &ip_configs {
            if config.enable
                && let IfaceIpModelConfig::Static { ipv4: Some(ipv4_addr), ipv4_mask, .. } =
                    &config.ip_model
            {
                let ip = IpAddr::V4(*ipv4_addr);
                let prefix_len = *ipv4_mask;
                tracing::info!(
                    "Re-applying WAN static IP: {ip}/{prefix_len} on {}",
                    config.iface_name
                );
                landscape::netlink::address::set_iface_ip(&config.iface_name, ip, prefix_len).await;
            }
        }
    }
}
