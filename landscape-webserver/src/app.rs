use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use arc_swap::ArcSwap;

use landscape::{
    cert::{account_service::CertAccountService, order_service::CertService},
    dhcp_server::dhcp_v4_service::DHCPv4ServerManagerService,
    dns::{
        ddns_service::DdnsService, provider_profile_service::DnsProviderProfileService,
        redirect_service::DNSRedirectService, rule_service::DNSRuleService,
        upstream_service::DnsUpstreamService,
    },
    docker::LandscapeDockerService,
    enrolled_device::service::EnrolledDeviceService,
    firewall::{blacklist_service::FirewallBlacklistService, FirewallServiceManagerService},
    flow::{dst_ip_rule_service::DstIpRuleService, rule_service::FlowRuleService},
    geo::{ip_service::GeoIpService, site_service::GeoSiteService},
    iface::{
        ipconfig_service::IfaceIpServiceManagerService,
        mss_clamp_service::MssClampServiceManagerService, nat_service::NatServiceManagerService,
        pppd_service::PPPDServiceConfigManagerService,
        static_nat_mapping_service::StaticNatMappingService, IfaceManagerService,
    },
    ipv6::{ipv6pd_service::DHCPv6ClientManagerService, lan_service_v2::LanIPv6ManagerService},
    metric::MetricService,
    route::{
        lan_service::RouteLanServiceManagerService, wan_service::RouteWanServiceManagerService,
        IpRouteService,
    },
    sys_service::{
        config_service::LandscapeConfigService, dns_service::LandscapeDnsService,
        ebpf_service::LandscapeEbpfService,
    },
    wifi::WifiServiceManagerService,
};

use landscape_common::{
    config::AuthRuntimeConfig, database::LandscapeStore, iface::ip_config::IfaceIpModelConfig,
    service::controller::ControllerService,
};

use crate::gateway_runtime::GatewayService;

#[allow(dead_code)]
#[derive(Clone)]
pub struct LandscapeApp {
    pub home_path: PathBuf,
    pub auth: Arc<ArcSwap<AuthRuntimeConfig>>,
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

    pub dhcp_v4_server_service: DHCPv4ServerManagerService,

    /// Metric
    pub metric_service: MetricService,

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
    pub(crate) static_nat_mapping_config_service: StaticNatMappingService,

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
    pub(crate) async fn validate_zone<C: landscape_common::iface::config::ZoneAwareConfig>(
        &self,
        config: &C,
    ) -> Result<(), landscape_common::service::ServiceConfigError> {
        use landscape_common::iface::config::{IfaceZoneType, ZoneRequirement};
        use landscape_common::service::ServiceConfigError;

        let iface_name = config.iface_name();
        let requirement = C::zone_requirement();

        // WanOrPpp: check if this is a PPP device first
        if matches!(requirement, ZoneRequirement::WanOrPpp) {
            if let Some(ppp_config) =
                self.pppd_service.get_config_by_name(iface_name.to_string()).await
            {
                // PPP service exists for this interface, verify the attached interface exists
                if self
                    .iface_config_service
                    .get_iface_config(ppp_config.attach_iface_name)
                    .await
                    .is_some()
                {
                    return Ok(()); // Valid PPP device, skip zone check
                }
            }
        }

        // docker0 special case: allow LanOnly services
        if iface_name == "docker0" && matches!(requirement, ZoneRequirement::LanOnly) {
            return Ok(());
        }

        // Regular zone check
        let iface_config =
            self.iface_config_service.get_iface_config(iface_name.to_string()).await.ok_or_else(
                || ServiceConfigError::IfaceNotFound { iface_name: iface_name.to_string() },
            )?;

        let allowed = match requirement {
            ZoneRequirement::WanOnly | ZoneRequirement::WanOrPpp => {
                matches!(iface_config.zone_type, IfaceZoneType::Wan)
            }
            ZoneRequirement::LanOnly => {
                matches!(iface_config.zone_type, IfaceZoneType::Lan)
            }
            ZoneRequirement::WanOrLan => {
                matches!(iface_config.zone_type, IfaceZoneType::Wan | IfaceZoneType::Lan)
            }
            ZoneRequirement::LanOrUndefined => {
                matches!(iface_config.zone_type, IfaceZoneType::Lan | IfaceZoneType::Undefined)
            }
        };

        if allowed {
            Ok(())
        } else {
            Err(ServiceConfigError::ZoneMismatch {
                service_name: C::service_kind(),
                iface_name: iface_name.to_string(),
            })
        }
    }

    pub(crate) async fn remove_direct_iface_service(&self, iface_name: &str) {
        self.mss_clamp_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.wan_ip_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.firewall_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.nat_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.ipv6_pd_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.route_wan_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.dhcp_v4_server_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.lan_ipv6_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.route_lan_service.delete_and_stop_iface_service(iface_name.to_string()).await;
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

        landscape_ebpf::map_setting::cleanup_pinned_maps();

        self.metric_service.stop_service().await;
        tracing::info!("Metric service stopped");

        self.ebpf_service.stop().await;
        tracing::info!("eBPF system service stopped");

        self.dns_service.stop().await;
        tracing::info!("DNS resolver conf restored");

        self.preserve_critical_ips().await;
        tracing::info!("Critical IPs preserved");
    }

    async fn preserve_critical_ips(&self) {
        let dhcp_configs =
            self.dhcp_v4_server_service.get_repository().list().await.unwrap_or_default();

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

        let ip_configs = self.wan_ip_service.get_repository().list().await.unwrap_or_default();

        for config in &ip_configs {
            if config.enable {
                if let IfaceIpModelConfig::Static { ipv4, ipv4_mask, .. } = &config.ip_model {
                    if let Some(ipv4_addr) = ipv4 {
                        let ip = IpAddr::V4(*ipv4_addr);
                        let prefix_len = *ipv4_mask;
                        tracing::info!(
                            "Re-applying WAN static IP: {ip}/{prefix_len} on {}",
                            config.iface_name
                        );
                        landscape::netlink::address::set_iface_ip(
                            &config.iface_name,
                            ip,
                            prefix_len,
                        )
                        .await;
                    }
                }
            }
        }
    }
}
