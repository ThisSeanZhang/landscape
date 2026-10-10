use std::{net::IpAddr, panic::AssertUnwindSafe, path::PathBuf, sync::Arc, time::Duration};

use arc_swap::ArcSwap;
use futures::FutureExt;
use landscape_core::lan_device::LanDeviceDirectory;
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
    wan_link_service::WanLinkServiceManagerService,
    wan_service::wan_route_service::RouteWanServiceManagerService,
    wifi::WifiServiceManagerService,
};

use landscape_common::{
    config::AuthRuntimeConfig,
    memtrack::MemoryHistory,
    service::controller::{ConfigStoreController, ConfigStoreServiceController},
    wan_link::{WanLinkKind, WanLinkV4Model},
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
    /// LAN device directory: authoritative runtime view of LAN devices
    /// (identity + addresses) for API point reads.
    pub lan_device_directory: Arc<LanDeviceDirectory>,
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
    /// WAN Link Service: owns the per-link WAN service set (v4 / nat / mss /
    /// firewall / pd) that replaced the per-iface service managers.
    pub(crate) wan_link_service: WanLinkServiceManagerService,
    pub(crate) docker_service: LandscapeDockerService,

    /// ipv6
    pub(crate) lan_ipv6_service: LanIPv6ManagerService,

    // Static NAT Mapping
    pub(crate) static_nat4_mapping_service: StaticNat4MappingService,
    pub(crate) static_nat6_mapping_service: StaticNat6MappingService,

    /// DNS Redirect Service
    pub(crate) dns_redirect_service: DNSRedirectService,

    pub(crate) dns_upstream_service: DnsUpstreamService,

    pub(crate) wifi_service: WifiServiceManagerService,

    pub(crate) ebpf_service: LandscapeEbpfService,
    pub(crate) enrolled_device_service: EnrolledDeviceService,

    pub(crate) cert_account_service: CertAccountService,
    pub(crate) cert_service: CertService,

    // Gateway
    pub(crate) gateway_service: GatewayService,
}

impl LandscapeApp {
    pub(crate) async fn remove_direct_iface_service(&self, iface_name: &str) {
        // The WAN link service owns the former per-iface WAN services
        // (v4 / nat / mss / firewall / pd, incl. pppd links): any link
        // attached to this iface goes away with the iface.
        match self.wan_link_service.list().await {
            Ok(links) => {
                for link in links {
                    if link.attach_iface_name == iface_name {
                        if let Err(error) =
                            self.wan_link_service.delete_and_stop_service(link.id).await
                        {
                            tracing::error!(
                                "failed to remove WAN link {} for {iface_name}: {error:?}",
                                link.id
                            );
                        }
                        // A pppd link leaves its ppp device's iface config row
                        // behind: drop it with the link (the cleanup the old
                        // `delete_ppp_iface` cascade used to do).
                        if let WanLinkKind::Pppd { ppp_iface_name, .. } = &link.kind {
                            let _ = self.iface_config_service.delete(ppp_iface_name.clone()).await;
                        }
                    }
                }
            }
            Err(error) => {
                tracing::error!(%error, "listing WAN links for '{iface_name}' failed")
            }
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
    }

    pub async fn shutdown(&self) {
        tracing::info!("Shutting down all services...");

        run_shutdown_phase("preserve_critical_ips", || async {
            self.preserve_critical_ips().await;
            tracing::info!("Critical IPs preserved");
        })
        .await;

        run_shutdown_phase("gateway_service", || async {
            self.gateway_service.shutdown_and_wait(Duration::from_secs(10)).await;
            tracing::info!("Gateway service stopped");
        })
        .await;

        run_shutdown_phase("ddns_service", || async {
            self.ddns_service.shutdown_and_wait(Duration::from_secs(10)).await;
            tracing::info!("DDNS service stopped");
        })
        .await;

        run_shutdown_phase("cert_service", || async {
            self.cert_service.shutdown_and_wait(Duration::from_secs(10)).await;
            tracing::info!("Cert service stopped");
        })
        .await;

        run_shutdown_phase("stop_service_managers", || async {
            tokio::join!(
                self.wan_link_service.get_service().stop_all(),
                self.route_wan_service.get_service().stop_all(),
                self.route_lan_service.get_service().stop_all(),
                self.dhcp_v4_server_service.get_service().stop_all(),
                self.lan_ipv6_service.get_service().stop_all(),
                self.wifi_service.get_service().stop_all(),
            );
            tracing::info!("All service managers stopped");
        })
        .await;

        run_shutdown_phase("preserve_critical_ips_after_stop", || async {
            self.preserve_critical_ips().await;
            tracing::info!("Critical IPs preserved after service stop");
        })
        .await;

        landscape_ebpf::maps::cleanup_pinned_maps();

        run_shutdown_phase("metric_service", || async {
            self.metric_service.stop_service().await;
            tracing::info!("Metric service stopped");
        })
        .await;

        run_shutdown_phase("ebpf_service", || async {
            self.ebpf_service.stop().await;
            tracing::info!("eBPF system service stopped");
        })
        .await;

        run_shutdown_phase("dns_service", || async {
            self.dns_service.stop().await;
            tracing::info!("DNS resolver conf restored");
        })
        .await;

        // Time sync keeps the clock sane for every other service, stop it last.
        run_shutdown_phase("time_service", || async {
            self.time_service.stop().await;
            tracing::info!("Time sync service stopped");
        })
        .await;
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

        let wan_links = self.wan_link_service.list().await.unwrap_or_default();

        for link in &wan_links {
            if link.v4.enable
                && let WanLinkV4Model::Static {
                    ipv4: Some(ipv4_addr),
                    ipv4_mask: Some(prefix_len),
                    ..
                } = &link.v4.model
            {
                let ip = IpAddr::V4(*ipv4_addr);
                tracing::info!(
                    "Re-applying WAN static IP: {ip}/{prefix_len} on {}",
                    link.attach_iface_name
                );
                landscape::netlink::address::set_iface_ip(&link.attach_iface_name, ip, *prefix_len)
                    .await;
            }
        }
    }
}

async fn run_shutdown_phase<F, Fut>(name: &'static str, phase: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if let Err(payload) = AssertUnwindSafe(phase()).catch_unwind().await {
        tracing::error!("shutdown phase '{name}' panicked: {payload:?}; continuing shutdown");
    }
}
