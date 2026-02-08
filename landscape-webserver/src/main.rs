use std::{collections::HashMap, net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    handler::HandlerWithoutStateExt, http::StatusCode, response::IntoResponse, routing::get, Router,
};

use axum_server::tls_rustls::RustlsConfig;
use colored::Colorize;
use config_service::{
    dns_rule::get_dns_rule_config_paths, dst_ip_rule::get_dst_ip_rule_config_paths,
    firewall_rule::get_firewall_rule_config_paths, flow_rule::get_flow_rule_config_paths,
    geo_ip::get_geo_ip_config_paths, geo_site::get_geo_site_config_paths,
};
use landscape::{
    boot::{boot_check, log::init_logger},
    cert::load_or_generate_cert,
    config_service::mac_binding::MacBindingService,
    config_service::{
        dns::{redirect::DNSRedirectService, upstream::DnsUpstreamService},
        dns_rule::DNSRuleService,
        dst_ip_rule::DstIpRuleService,
        firewall_rule::FirewallRuleService,
        flow_rule::FlowRuleService,
        geo_ip_service::GeoIpService,
        geo_site_service::GeoSiteService,
        static_nat_mapping::StaticNatMappingService,
    },
    docker::LandscapeDockerService,
    firewall::FirewallServiceManagerService,
    iface::IfaceManagerService,
    metric::MetricService,
    route::IpRouteService,
    service::{
        dhcp_v4::DHCPv4ServerManagerService, ipconfig::IfaceIpServiceManagerService,
        ipv6pd::DHCPv6ClientManagerService, mss_clamp::MssClampServiceManagerService,
        nat_service::NatServiceManagerService, pppd_service::PPPDServiceConfigManagerService,
        ra::IPV6RAManagerService, route_lan::RouteLanServiceManagerService,
        route_wan::RouteWanServiceManagerService,
    },
    sys_service::{
        config_service::LandscapeConfigService, dns_service::LandscapeDnsService,
        ebpf_service::LandscapeEbpfService,
    },
    wifi::WifiServiceManagerService,
};
use landscape_common::config::route_lan::RouteLanServiceConfig;
use landscape_common::database::repository::Repository;
use landscape_common::dhcp::v4_server::config::DHCPv4ServiceConfig;
use landscape_common::{
    args::{LandscapeAction, LAND_ARGS, LAND_HOME_PATH},
    config::RuntimeConfig,
    error::LdResult,
    ipv6_pd::IAPrefixMap,
    service::controller_service_v2::ControllerService,
    VERSION,
};
use landscape_database::provider::LandscapeDBServiceProvider;
use sys_service::dns_service::get_dns_paths;
use tokio::sync::mpsc;
use tower_http::{services::ServeDir, trace::TraceLayer};

mod api;
mod auth;
mod config_service;
mod docker;
mod dump;
mod error;
mod iface;
mod metric;
mod redirect_https;
mod service;
mod sys_service;
mod sysinfo;

mod websocket;

use service::{
    dhcp_v4::get_dhcp_v4_service_paths, firewall::get_firewall_service_paths,
    mss_clamp::get_mss_clamp_service_paths,
};
use service::{icmp_ra::get_iface_icmpv6ra_paths, nat::get_iface_nat_paths};
use service::{ipconfig::get_iface_ipconfig_paths, ipv6pd::get_iface_pdclient_paths};
use service::{pppd::get_iface_pppd_paths, wifi::get_wifi_service_paths};
use tracing::info;

use crate::{
    config_service::{
        dns_redirect::get_dns_redirect_config_paths, dns_upstream::get_dns_upstream_config_paths,
        mac_binding::get_mac_binding_config_paths,
        static_nat_mapping::get_static_nat_mapping_config_paths,
    },
    service::{
        route::get_route_paths, route_lan::get_route_lan_paths, route_wan::get_route_wan_paths,
    },
    sys_service::config::get_config_paths,
};

const DNS_EVENT_CHANNEL_SIZE: usize = 128;
const DST_IP_EVENT_CHANNEL_SIZE: usize = 128;
const ROUTE_EVENT_CHANNEL_SIZE: usize = 128;

const UPLOAD_GEO_FILE_SIZE_LIMIT: usize = 100 * 1024 * 1024;

#[allow(dead_code)]
#[derive(Clone)]
pub struct LandscapeApp {
    pub home_path: PathBuf,
    pub dns_service: LandscapeDnsService,
    pub dns_rule_service: DNSRuleService,
    pub flow_rule_service: FlowRuleService,
    pub geo_site_service: GeoSiteService,
    pub fire_wall_rule_service: FirewallRuleService,
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
    iface_config_service: IfaceManagerService,
    /// Iface IP Service
    wan_ip_service: IfaceIpServiceManagerService,
    docker_service: LandscapeDockerService,

    /// pppd service
    pppd_service: PPPDServiceConfigManagerService,

    /// ipv6
    ipv6_pd_service: DHCPv6ClientManagerService,
    ipv6_ra_service: IPV6RAManagerService,

    // Static NAT Mapping
    static_nat_mapping_config_service: StaticNatMappingService,

    /// DNS Redirect Service
    dns_redirect_service: DNSRedirectService,

    dns_upstream_service: DnsUpstreamService,

    /// Mss Clamp Service
    mss_clamp_service: MssClampServiceManagerService,
    firewall_service: FirewallServiceManagerService,
    wifi_service: WifiServiceManagerService,
    nat_service: NatServiceManagerService,

    ebpf_service: LandscapeEbpfService,
    mac_binding_service: MacBindingService,
}

impl LandscapeApp {
    pub(crate) async fn remove_all_iface_service(&self, iface_name: &str) {
        self.mss_clamp_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.wan_ip_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.firewall_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.nat_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.ipv6_pd_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.route_wan_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.dhcp_v4_server_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.ipv6_ra_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.route_lan_service.delete_and_stop_iface_service(iface_name.to_string()).await;
        self.pppd_service.stop_pppds_by_attach_iface_name(iface_name.to_string()).await;
    }
}

async fn run(home_path: PathBuf, config: RuntimeConfig) -> LdResult<()> {
    let need_init_config = boot_check(&home_path)?;

    let crypto_provider = rustls::crypto::ring::default_provider();
    crypto_provider.install_default().unwrap();

    let db_store_provider = LandscapeDBServiceProvider::new(&config.store).await;

    db_store_provider.truncate_and_fit_from(need_init_config).await;

    // 初始化 App

    let dev_obs = landscape::observer::dev_observer().await;

    let (dns_service_tx, dns_service_rx) = mpsc::channel(DNS_EVENT_CHANNEL_SIZE);
    let (route_service_tx, route_service_rx) = mpsc::channel(ROUTE_EVENT_CHANNEL_SIZE);
    let (dst_ip_service_tx, dst_ip_service_rx) = mpsc::channel(DST_IP_EVENT_CHANNEL_SIZE);

    let geo_site_service =
        GeoSiteService::new(db_store_provider.clone(), dns_service_tx.clone()).await;

    let dns_upstream_service =
        DnsUpstreamService::new(db_store_provider.clone(), dns_service_tx.clone()).await;

    let dns_rule_service = DNSRuleService::new(
        db_store_provider.clone(),
        dns_service_tx.clone(),
        dns_upstream_service.clone(),
    )
    .await;

    let flow_rule_service = FlowRuleService::new(
        db_store_provider.clone(),
        dns_service_tx.clone(),
        route_service_tx.clone(),
    )
    .await;

    let dns_redirect_service =
        DNSRedirectService::new(db_store_provider.clone(), dns_service_tx.clone()).await;

    let metric_service = MetricService::new(home_path.clone(), config.metric.clone()).await;

    let dns_service = LandscapeDnsService::new(
        dns_service_rx,
        dns_rule_service.clone(),
        dns_redirect_service.clone(),
        geo_site_service.clone(),
        dns_upstream_service.clone(),
        config.dns.clone(),
        Some(metric_service.data.dns_metric.get_msg_channel()),
    )
    .await;
    let fire_wall_rule_service = FirewallRuleService::new(db_store_provider.clone()).await;

    let geo_ip_service =
        GeoIpService::new(db_store_provider.clone(), dst_ip_service_tx.clone()).await;
    let dst_ip_rule_service =
        DstIpRuleService::new(db_store_provider.clone(), geo_ip_service.clone(), dst_ip_service_rx)
            .await;

    let config_service =
        LandscapeConfigService::new(config.clone(), db_store_provider.clone()).await;

    let route_service = IpRouteService::new(route_service_rx, db_store_provider.flow_rule_store());
    let ebpf_service = LandscapeEbpfService::new();

    let static_nat_mapping_config_service =
        StaticNatMappingService::new(db_store_provider.clone()).await;

    let mac_binding_service = MacBindingService::new(db_store_provider.clone()).await;

    let route_lan_service = RouteLanServiceManagerService::new(
        db_store_provider.clone(),
        route_service.clone(),
        dev_obs.resubscribe(),
    )
    .await;
    let route_wan_service =
        RouteWanServiceManagerService::new(db_store_provider.clone(), dev_obs.resubscribe()).await;

    let mss_clamp_service =
        MssClampServiceManagerService::new(db_store_provider.clone(), dev_obs.resubscribe()).await;

    let firewall_service =
        FirewallServiceManagerService::new(db_store_provider.clone(), dev_obs.resubscribe()).await;

    let nat_service =
        NatServiceManagerService::new(db_store_provider.clone(), dev_obs.resubscribe()).await;

    let wifi_service = WifiServiceManagerService::new(db_store_provider.clone()).await;

    let iface_config_service = IfaceManagerService::new(db_store_provider.clone()).await;

    let dhcp_v4_server_service = DHCPv4ServerManagerService::new(
        route_service.clone(),
        db_store_provider.clone(),
        dev_obs.resubscribe(),
    )
    .await;

    let wan_ip_service = IfaceIpServiceManagerService::new(
        route_service.clone(),
        db_store_provider.clone(),
        dev_obs.resubscribe(),
    )
    .await;

    let docker_service = LandscapeDockerService::new(home_path.clone(), route_service.clone());

    let pppd_service =
        PPPDServiceConfigManagerService::new(db_store_provider.clone(), route_service.clone())
            .await;

    let prefix_map = IAPrefixMap::new();
    let ipv6_pd_service = DHCPv6ClientManagerService::new(
        db_store_provider.clone(),
        dev_obs.resubscribe(),
        route_service.clone(),
        prefix_map.clone(),
    )
    .await;
    let ipv6_ra_service = IPV6RAManagerService::new(
        db_store_provider.clone(),
        dev_obs.resubscribe(),
        route_service.clone(),
        prefix_map,
    )
    .await;

    docker_service.start_to_listen_event().await;

    metric_service.start_service().await;
    let landscape_app_status = LandscapeApp {
        home_path: home_path.clone(),
        dns_service,
        dns_rule_service,
        flow_rule_service,
        geo_site_service,
        fire_wall_rule_service,
        dst_ip_rule_service,
        geo_ip_service,
        config_service,
        metric_service,
        route_service,
        dhcp_v4_server_service,
        wan_ip_service,

        route_lan_service,
        route_wan_service,

        docker_service,

        pppd_service,

        // IPV6
        ipv6_pd_service,
        ipv6_ra_service,
        static_nat_mapping_config_service,
        dns_redirect_service,
        dns_upstream_service,
        iface_config_service,
        mss_clamp_service,
        firewall_service,
        wifi_service,
        nat_service,
        // ebpf
        ebpf_service,
        mac_binding_service,
    };

    // 初始化结束
    let tls_config = load_or_generate_cert(home_path.clone()).await;
    landscape_common::sys_config::init_sysctl_setting();

    let addr = SocketAddr::from((config.web.address, config.web.https_port));
    // spawn a second server to redirect http requests to this server
    tokio::spawn(redirect_https::redirect_http_to_https(config.web.clone()));
    let web_root = config.web.web_root.clone();
    let service = (move || handle_404(web_root)).into_service();

    let serve_dir = ServeDir::new(&config.web.web_root).not_found_service(service);

    let auth_share = Arc::new(config.auth.clone());
    auth::output_sys_token(&config.auth).await;
    let source_route = Router::new()
        .nest("/iface", iface::get_network_paths().await)
        .nest("/metric", metric::get_metric_service_paths().await)
        .nest(
            "/sys_service",
            Router::new()
                .merge(get_dns_paths().await)
                .merge(get_config_paths().await)
                .nest("/docker", docker::get_docker_paths().await),
        )
        .nest(
            "/config",
            Router::new()
                .merge(get_dns_rule_config_paths().await)
                .merge(get_firewall_rule_config_paths().await)
                .merge(get_flow_rule_config_paths().await)
                .merge(get_geo_site_config_paths().await)
                .merge(get_geo_ip_config_paths().await)
                .merge(get_dst_ip_rule_config_paths().await)
                .merge(get_static_nat_mapping_config_paths().await)
                .merge(get_dns_redirect_config_paths().await)
                .merge(get_dns_upstream_config_paths().await)
                .merge(get_mac_binding_config_paths().await),
        )
        .nest(
            "/services",
            Router::new()
                .merge(get_route_paths().await)
                .merge(get_route_wan_paths().await)
                .merge(get_route_lan_paths().await)
                .merge(get_mss_clamp_service_paths().await)
                .merge(get_firewall_service_paths().await)
                .merge(get_iface_ipconfig_paths().await)
                .merge(get_dhcp_v4_service_paths().await)
                .merge(get_iface_pppd_paths().await)
                .merge(get_wifi_service_paths().await)
                .merge(get_iface_pdclient_paths().await)
                .merge(get_iface_icmpv6ra_paths().await)
                .merge(get_iface_nat_paths().await),
        )
        .with_state(landscape_app_status.clone())
        .nest("/sysinfo", sysinfo::get_sys_info_route())
        .route_layer(axum::middleware::from_fn_with_state(auth_share.clone(), auth::auth_handler));

    let sockets_route = Router::new()
        .nest("/docker", websocket::docker_task::get_docker_images_socks_paths().await)
        .nest("/pty", websocket::web_pty::get_web_pty_socks_paths().await)
        .with_state(landscape_app_status.clone())
        .merge(dump::get_tump_router())
        .route_layer(axum::middleware::from_fn_with_state(
            auth_share.clone(),
            auth::auth_handler_from_query,
        ));

    let api_route = Router::new()
        // 资源路由 需要认证
        .nest("/src", source_route)
        // 认证方式有别
        .nest("/sock", sockets_route)
        // 认证路由
        .nest("/auth", auth::get_auth_route(auth_share));
    let app = Router::new()
        .nest("/api", api_route)
        // .nest("/sock", sockets_route)
        .route("/foo", get(|| async { "Hi from /foo" }))
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http());

    axum_server::bind_rustls(addr, RustlsConfig::from_config(tls_config.into()))
        .serve(app.into_make_service())
        .await
        .unwrap();

    // axum::serve(listener, app.layer(TraceLayer::new_for_http())).await.unwrap();
    Ok(())
}

#[tokio::main]
async fn main() -> LdResult<()> {
    let home_path = LAND_HOME_PATH.clone();

    let lock_exists = home_path.join(landscape_common::INIT_LOCK_FILE_NAME).exists();
    let init_exists = home_path.join(landscape_common::INIT_FILE_NAME).exists();
    let db_exists = home_path.join(landscape_common::LANDSCAPE_DB_SQLITE_NAME).exists();

    let config = RuntimeConfig::new((*LAND_ARGS).clone());

    if let Err(e) = init_logger(config.log.clone()) {
        panic!("init log error: {e:?}");
    }

    if config.auto {
        if lock_exists || init_exists || db_exists {
            let mut reasons = vec![];
            if lock_exists {
                reasons
                    .push(format!("lock file ({}) exists", landscape_common::INIT_LOCK_FILE_NAME));
            }
            if init_exists {
                reasons.push(format!("init toml ({}) exists", landscape_common::INIT_FILE_NAME));
            }
            if db_exists {
                reasons.push(format!(
                    "database ({}) exists",
                    landscape_common::LANDSCAPE_DB_SQLITE_NAME
                ));
            }
            tracing::info!("Auto init skipped: {}.", reasons.join(", "));
        } else {
            do_auto_init(&home_path, &config).await?;
        }
    }

    banner(&config);

    let args = &LAND_ARGS;
    if let Some(action) = &args.action {
        match action {
            LandscapeAction::Db { rollback, times } => {
                landscape_database::provider::db_action(&config.store, rollback, times).await;
                Ok(())
            }
        }
    } else {
        run(home_path, config).await
    }
}

async fn do_auto_init(home_path: &PathBuf, config: &RuntimeConfig) -> LdResult<()> {
    use std::io::Write;

    let mut interface_map = HashMap::new();
    let devs = landscape::get_all_devices().await;
    tracing::info!("Discovered {} total interfaces.", devs.len());
    for dev in devs {
        interface_map.insert(dev.name.clone(), dev);
    }

    let default_configs = landscape::gen_default_config(&interface_map);
    if default_configs.is_empty() {
        tracing::warn!("Auto init: no physical interfaces found.");
        return Ok(());
    }

    let db_store_provider = LandscapeDBServiceProvider::new(&config.store).await;
    let store = db_store_provider.iface_store();
    for cfg in default_configs {
        store.set_or_update_model(cfg.name.clone(), cfg).await.unwrap();
    }

    // 创建 lock 文件 避免重复进行初始化
    let lock_path = home_path.join(landscape_common::INIT_LOCK_FILE_NAME);
    let mut file = std::fs::File::create(lock_path)?;
    file.write_all(landscape::boot::INIT_LOCK_FILE_CONTENT.as_bytes())?;

    // 初始化 br_lan 的服务
    let dhcp_store = db_store_provider.dhcp_v4_server_store();
    dhcp_store
        .set_or_update_model(
            landscape_common::LANDSCAPE_DEFAULT_LAN_NAME.to_string(),
            DHCPv4ServiceConfig::default(),
        )
        .await
        .unwrap();

    let route_lan_store = db_store_provider.route_lan_service_store();
    route_lan_store
        .set_or_update_model(
            landscape_common::LANDSCAPE_DEFAULT_LAN_NAME.to_string(),
            RouteLanServiceConfig {
                iface_name: landscape_common::LANDSCAPE_DEFAULT_LAN_NAME.to_string(),
                enable: true,
                update_at: landscape_common::utils::time::get_f64_timestamp(),
                static_routes: None,
            },
        )
        .await
        .unwrap();

    tracing::info!(
        "Auto init: bridge, IP, DHCP and Route services configuration saved to database."
    );
    Ok(())
}

/// NOT Found
async fn handle_404(web_root: PathBuf) -> impl IntoResponse {
    let path = web_root.join("index.html");
    if path.exists() {
        if let Ok(content) = std::fs::read_to_string(path) {
            return (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/html")], content)
                .into_response();
        }
    }
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

fn banner(config: &RuntimeConfig) {
    let banner = format!(
        r#"
██╗      █████╗ ███╗   ██╗██████╗ ███████╗ ██████╗ █████╗ ██████╗ ███████╗
██║     ██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝
██║     ███████║██╔██╗ ██║██║  ██║███████╗██║     ███████║██████╔╝█████╗
██║     ██╔══██║██║╚██╗██║██║  ██║╚════██║██║     ██╔══██║██╔═══╝ ██╔══╝
███████╗██║  ██║██║ ╚████║██████╔╝███████║╚██████╗██║  ██║██║     ███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚══════╝

██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝
██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║
╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝ (v{version})

Landscape Router is licensed under the GPL-3.0 License

Github: https://github.com/ThisSeanZhang/landscape
Doc   : https://landscape.whileaway.dev
"#,
        version = VERSION
    );
    let config_str = config.to_string_summary();
    info!("{}{}", banner, config_str);
    if !config.log.log_output_in_terminal {
        // 当日志不在 terminal 直接展示时, 仅输出一些信息
        let banner = banner.bright_blue().bold();
        let config_str = config_str.green();
        println!("{}", banner);
        println!("{}", config_str);
    }
}
