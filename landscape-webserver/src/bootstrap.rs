use std::{path::PathBuf, sync::Arc, time::Instant};

use arc_swap::ArcSwap;

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
    sys_service::route::IpRouteService,
    sys_service::{
        config_service::LandscapeConfigService, dns_service::LandscapeDnsService,
        ebpf_service::LandscapeEbpfService, gateway::GatewayService,
    },
    wan_link_service::WanLinkServiceManagerService,
    wan_link_service::probe::IcmpV4Probe,
    wan_service::generate_wan_iid,
    wan_service::wan_route_service::RouteWanServiceManagerService,
    wifi::WifiServiceManagerService,
};

use landscape_common::{
    args::LAND_ARGS,
    database::{error::DbError, store::ConfigStore},
    event::hub::EventHub,
    sys_config::{AuthRuntimeConfig, RuntimeConfig},
};
use landscape_core::lan_device::LanDeviceDirectory;
use landscape_core::pd_prefix::IAPrefixMap;
use landscape_core::time::SyncTimeService;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_ebpf::chain::ip6_dao_event::Ip6DaoEventSource;
use landscape_ebpf::maps::LandscapeMapPath;
use landscape_ebpf::runtime::EbpfRuntime;
use tokio::sync::mpsc;

use crate::app::{LandscapeApp, ManagedServices, SystemServices};
use crate::{DNS_EVENT_CHANNEL_SIZE, DST_IP_EVENT_CHANNEL_SIZE, StartupError, log_startup_phase};

pub(crate) struct BootstrappedApp {
    pub app: LandscapeApp,
    pub auth: Arc<ArcSwap<AuthRuntimeConfig>>,
    pub ebpf_paths: Arc<LandscapeMapPath>,
}

pub(crate) async fn build_app(
    home_path: PathBuf,
    config: &RuntimeConfig,
    db_store_provider: LandscapeDBServiceProvider,
    time_service: SyncTimeService,
) -> Result<BootstrappedApp, StartupError> {
    let startup_start = Instant::now();

    macro_rules! startup_phase {
        ($name:literal, $expr:expr) => {{
            let phase_start = Instant::now();
            let value = $expr;
            log_startup_phase($name, phase_start, startup_start);
            value
        }};
    }

    // init App

    // init eBPF runtime (map space + TC/XDP chain managers)
    let ebpf_rt = Arc::new(
        EbpfRuntime::init(&LAND_ARGS.ebpf_map_space, LAND_ARGS.try_native_xdp.clone())
            .expect("failed to init eBPF runtime"),
    );
    let ebpf_paths = ebpf_rt.paths().clone();

    let event_hub = EventHub::new();
    startup_phase!("observer.dev_observer", landscape::observer::dev_observer(&event_hub).await);
    let device_sender = event_hub.enrolled_device_sender();
    let ipv4_assign_sender = event_hub.ipv4_sender();
    let ipv6_assign_sender = event_hub.ipv6_sender();
    let ipv6_prefix_sender = event_hub.ipv6_prefix_sender();
    let lan_discovery_sender = event_hub.lan_discovery_sender();
    let lan_device_sender = event_hub.lan_device_sender();
    let event_handle = event_hub.spawn();

    startup_phase!(
        "xdp_redirect_able.clear",
        landscape_ebpf::maps::redirect_able::clear_xdp_redirect_able(&ebpf_paths)
    );

    let (dns_service_tx, dns_service_rx) = mpsc::channel(DNS_EVENT_CHANNEL_SIZE);
    let (dst_ip_service_tx, _) = tokio::sync::broadcast::channel(DST_IP_EVENT_CHANNEL_SIZE);

    let geo_site_service = startup_phase!(
        "geo_site_service.new",
        GeoSiteService::new(db_store_provider.clone(), dns_service_tx.clone()).await
    );

    let dns_upstream_service = startup_phase!(
        "dns_upstream_service.new",
        DnsUpstreamService::new(db_store_provider.clone(), dns_service_tx.clone()).await
    );

    let dns_rule_service = startup_phase!(
        "dns_rule_service.new",
        DNSRuleService::new(
            db_store_provider.clone(),
            dns_service_tx.clone(),
            dns_upstream_service.clone(),
        )
        .await?
    );

    let route_service =
        startup_phase!("route_service.new", IpRouteService::new(ebpf_rt.clone().route_table()));
    route_service.spawn_kernel_default_sync_loop();

    let flow_rule_service = startup_phase!(
        "flow_rule_service.new",
        FlowRuleService::new(
            db_store_provider.clone(),
            dns_service_tx.clone(),
            route_service.clone(),
            event_handle.subscribe_device(),
            ebpf_rt.clone().flow_rules(),
        )
        .await
    );

    let dns_redirect_service = startup_phase!(
        "dns_redirect_service.new",
        DNSRedirectService::new(db_store_provider.clone(), dns_service_tx.clone()).await
    );

    let metric_service = startup_phase!(
        "metric_service.new",
        MetricService::new(
            home_path.clone(),
            config.metric.clone(),
            Arc::new(ebpf_rt.metric_source_factory()),
        )
        .await
        .map_err(StartupError::Metric)?
    );

    let cert_account_service = startup_phase!(
        "cert_account_service.new",
        CertAccountService::new(db_store_provider.clone()).await
    );
    let cert_service = startup_phase!(
        "cert_service.new",
        CertService::new(
            db_store_provider.clone(),
            cert_account_service.clone(),
            Some(dns_redirect_service.clone()),
        )
        .await
    );
    let phase_start = Instant::now();
    if let Err(e) = cert_service.reload_api_tls_mapping().await {
        return Err(StartupError::Cert(format!("failed to load api tls certificates: {e}")));
    }
    log_startup_phase("cert_service.reload_api_tls_mapping", phase_start, startup_start);
    // Gateway
    let gateway_store = db_store_provider.gateway_http_upstream_store();
    let gateway_service = startup_phase!(
        "gateway_service.init_service",
        GatewayService::init_service(
            gateway_store,
            config.gateway.clone(),
            &cert_service,
            dns_redirect_service.clone(),
        )
        .await?
    );

    let enrolled_devices = db_store_provider.enrolled_device_store().list().await.map_err(|e| {
        StartupError::Database(DbError::Internal(format!("failed to list enrolled devices: {e}")))
    })?;
    let lan_device_directory = startup_phase!("lan_device.new", {
        LanDeviceDirectory::new(
            enrolled_devices.clone(),
            lan_device_sender,
            event_handle.subscribe_device(),
            event_handle.subscribe_ipv4_assign(),
            event_handle.subscribe_ipv6_assign(),
            event_handle.subscribe_lan_discovery(),
        )
    });
    // Shared LAN hostname config: hot-reloaded by the config service and read
    // by the DNS local resolver and the DHCPv4 server (options 15/119).
    let lan_domain_state = Arc::new(ArcSwap::from_pointee(config.lan_hostname.clone()));
    let dns_service = startup_phase!(
        "dns_service.new",
        LandscapeDnsService::new(
            dns_service_rx,
            dns_rule_service.clone(),
            dns_redirect_service.clone(),
            geo_site_service.clone(),
            dns_upstream_service.clone(),
            route_service.clone(),
            config.dns.clone(),
            cert_service.clone(),
            metric_service.dns_metric_reporter(),
            lan_device_directory.clone(),
            lan_domain_state.clone(),
            Arc::new(ebpf_rt.dns_result_sink()),
            Arc::new(ebpf_rt.flow_socket_registrar()),
        )
        .await
    );
    let dns_provider_profile_service =
        DnsProviderProfileService::new(db_store_provider.clone()).await;
    let prefix_map = IAPrefixMap::new();

    let dao_event_source = match Ip6DaoEventSource::spawn(ebpf_paths.clone()) {
        Ok(source) => {
            tracing::info!("ip6_dao_event ringbuf consumer started");
            Some(Arc::new(source))
        }
        Err(e) => {
            tracing::warn!("ip6_dao_event ringbuf consumer failed to start: {e}");
            None
        }
    };
    let lan_ipv6_service = LanIPv6ManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        event_handle.subscribe_device(),
        event_handle.subscribe_ipv6_prefix(),
        route_service.clone(),
        prefix_map.clone(),
        ipv6_assign_sender.clone(),
        ebpf_rt.clone().mac_binding(),
        dao_event_source,
        ebpf_rt.clone().ipv6_dao_filter(),
    )
    .await;
    let ddns_service = DdnsService::new(
        db_store_provider.clone(),
        route_service.clone(),
        prefix_map.clone(),
        lan_device_directory.clone(),
        event_handle.subscribe_lan_device(),
        event_handle.subscribe_ipv6_prefix(),
    )
    .await;

    let geo_ip_service =
        GeoIpService::new(db_store_provider.clone(), dst_ip_service_tx.clone()).await;
    let dst_ip_rule_service = DstIpRuleService::new(
        db_store_provider.clone(),
        geo_ip_service.clone(),
        dst_ip_service_tx.subscribe(),
        ebpf_rt.clone().flow_rules(),
    )
    .await;
    let firewall_blacklist_service = FirewallBlacklistService::new(
        db_store_provider.clone(),
        geo_ip_service.clone(),
        dst_ip_service_tx.subscribe(),
        ebpf_rt.clone().firewall(),
    )
    .await;

    let config_service =
        LandscapeConfigService::new(config.clone(), db_store_provider.clone()).await;

    let ebpf_service = LandscapeEbpfService::new(ebpf_rt.start_neigh_update());

    let static_nat4_mapping_service = StaticNat4MappingService::new(
        db_store_provider.clone(),
        event_handle.subscribe_device(),
        ebpf_rt.clone().nat(),
    )
    .await;

    let shared_wan_iid = Arc::new(generate_wan_iid());
    let static_nat6_mapping_service = StaticNat6MappingService::new(
        db_store_provider.clone(),
        lan_device_directory.clone(),
        shared_wan_iid.clone(),
        ebpf_rt.clone().nat(),
    )
    .await;

    let enrolled_device_service =
        EnrolledDeviceService::new(db_store_provider.clone(), device_sender).await;

    let route_lan_service = RouteLanServiceManagerService::new(
        db_store_provider.clone(),
        route_service.clone(),
        event_handle.subscribe_iface(),
        ebpf_rt.clone().lan_route(),
    )
    .await?;
    let route_wan_service = RouteWanServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        ebpf_rt.clone().wan_route(),
    )
    .await?;

    // WAN link service: replaces the former per-iface WAN service managers
    // (ipconfig / nat / mss clamp / firewall / ipv6-pd / pppd).
    let wan_link_service = WanLinkServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        route_service.clone(),
        ebpf_rt.clone(),
        Arc::new(IcmpV4Probe),
        prefix_map.clone(),
        ipv6_prefix_sender.clone(),
        shared_wan_iid,
    )
    .await;

    let wifi_service = WifiServiceManagerService::new(db_store_provider.clone()).await?;

    let iface_config_service = IfaceManagerService::new(db_store_provider.clone()).await;

    let dhcp_v4_server_service = DHCPv4ServerManagerService::new(
        route_service.clone(),
        db_store_provider.clone(),
        cert_service.api_tls_resolver(),
        config.dns.clone(),
        lan_domain_state,
        event_handle.subscribe_iface(),
        ipv4_assign_sender,
        lan_discovery_sender,
        event_handle.subscribe_device(),
        ebpf_rt.clone().mac_binding(),
    )
    .await;

    let docker_service = LandscapeDockerService::new(home_path.clone(), route_service.clone());

    startup_phase!(
        "docker_service.start_to_listen_event",
        docker_service.start_to_listen_event().await
    );

    startup_phase!("metric_service.start_service", metric_service.start_service().await);
    // RAM 环形缓冲仅服务实时查询;分钟级持久化由 metric_service(MemRecording)独立负责。
    let memory_history = landscape_common::memtrack::start_sampler();
    let auth_share = Arc::new(ArcSwap::from_pointee(config.auth.clone()));
    let app = LandscapeApp {
        home_path,
        ebpf_paths: ebpf_paths.clone(),
        route_service,
        lan_device_directory,
        memory_history,
        docker_service,
        ebpf_service,
        system: SystemServices {
            auth: auth_share.clone(),
            config_service,
            dns_service,
            time_service,
            metric_service,
        },
        managed: ManagedServices {
            dns_provider_profile_service,
            dns_rule_service,
            dns_redirect_service,
            dns_upstream_service,
            ddns_service,
            flow_rule_service,
            dst_ip_rule_service,
            geo_site_service,
            geo_ip_service,
            firewall_blacklist_service,
            dhcp_v4_server_service,
            route_lan_service,
            route_wan_service,
            iface_config_service,
            wan_link_service,
            lan_ipv6_service,
            static_nat4_mapping_service,
            static_nat6_mapping_service,
            wifi_service,
            enrolled_device_service,
            cert_account_service,
            cert_service,
            gateway_service,
        },
    };

    Ok(BootstrappedApp { app, auth: auth_share, ebpf_paths })
}
