use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;

use axum::{
    handler::HandlerWithoutStateExt, http::StatusCode, response::IntoResponse, routing::get, Router,
};

use axum_server::tls_rustls::RustlsConfig;
use colored::Colorize;

use landscape::{
    boot::{boot_check, log::init_logger, write_config_toml, write_init_lock},
    cert::build_tls_server_config_with_shared_resolver,
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
    ipv6::{ipv6pd_service::DHCPv6ClientManagerService, lan_service::LanIPv6ManagerService},
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
use landscape_common::route::lan::RouteLanServiceConfig;
use landscape_common::{
    args::{DbAction, LandscapeAction, LAND_ARGS, LAND_HOME_PATH},
    concurrency::{runtime_thread_name_fn, spawn_task, task_label, thread_name},
    config::RuntimeConfig,
    error::LdResult,
    event::hub::EventHub,
    ipv6_pd::IAPrefixMap,
    VERSION,
};
use landscape_common::{config::InitConfig, dhcp::v4_server::config::DHCPv4ServiceConfig};
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::repository::Repository;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::mpsc;
use tower_http::{services::ServeDir, trace::TraceLayer};
use utoipa_scalar::{Scalar, Servable};

mod api;
mod app;
mod auth;
mod cert;
mod devices;
mod dns;
mod docker;
mod dump;
mod error;
mod firewall;
mod flow;
mod gateway;
mod gateway_runtime;
mod geo;
mod interfaces;
mod metrics;
mod nat;
mod openapi;
mod redirect_https;
mod services;
mod system;
mod websocket;

pub use app::LandscapeApp;

use crate::gateway_runtime::{GatewayService, GatewayTlsConfig};
use tracing::info;

const DNS_EVENT_CHANNEL_SIZE: usize = 128;
const DST_IP_EVENT_CHANNEL_SIZE: usize = 128;
const ROUTE_EVENT_CHANNEL_SIZE: usize = 128;

const UPLOAD_GEO_FILE_SIZE_LIMIT: usize = 100 * 1024 * 1024;

fn log_startup_phase(phase: &str, phase_start: Instant, startup_start: Instant) {
    tracing::info!(
        "startup phase={} elapsed_ms={} since_run_ms={}",
        phase,
        phase_start.elapsed().as_millis(),
        startup_start.elapsed().as_millis()
    );
}

async fn prepare_startup_init(
    home_path: &Path,
    config: &RuntimeConfig,
    init_config_to_import: Option<InitConfig>,
) -> LdResult<LandscapeDBServiceProvider> {
    let startup_start = Instant::now();

    macro_rules! startup_phase {
        ($name:literal, $expr:expr) => {{
            let phase_start = Instant::now();
            let value = $expr;
            log_startup_phase($name, phase_start, startup_start);
            value
        }};
    }

    let init_file_config_to_persist = init_config_to_import
        .as_ref()
        .filter(|init_config| !init_config.version.is_empty())
        .map(|init_config| init_config.config.clone());

    let crypto_provider = rustls::crypto::ring::default_provider();
    crypto_provider.install_default().unwrap();

    let db_store_provider = startup_phase!(
        "db_store_provider.new",
        LandscapeDBServiceProvider::new(&config.store).await
    );

    if let Some(init_config) = init_config_to_import {
        startup_phase!("db_store_provider.truncate_and_fit_from", {
            LandscapeDBServiceProvider::validate_init_config_can_import(init_config.clone())
                .await?;
            db_store_provider
                .truncate_and_fit_from_before_commit(init_config, || {
                    if let Some(config) = init_file_config_to_persist {
                        write_config_toml(home_path, config)?;
                    }
                    Ok(())
                })
                .await?
        });
        startup_phase!("write_init_lock", write_init_lock(home_path)?);
    }

    Ok(db_store_provider)
}

async fn run_system(
    home_path: PathBuf,
    config: RuntimeConfig,
    db_store_provider: LandscapeDBServiceProvider,
) -> LdResult<()> {
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

    // init eBPF instance
    landscape_ebpf::chain::tc_manager::TcChainManager::instance();
    landscape_ebpf::chain::xdp_manager::XdpChainManager::instance();

    let event_hub = EventHub::new();
    startup_phase!("observer.dev_observer", landscape::observer::dev_observer(&event_hub).await);
    let device_sender = event_hub.enrolled_device_sender();
    let ipv4_assign_sender = event_hub.ipv4_sender();
    let ipv6_assign_sender = event_hub.ipv6_sender();
    let ipv6_prefix_sender = event_hub.ipv6_prefix_sender();
    let event_handle = event_hub.spawn();

    startup_phase!(
        "xdp_redirect_able.clear",
        landscape_ebpf::map_setting::redirect_able::clear_xdp_redirect_able()
    );

    let (dns_service_tx, dns_service_rx) = mpsc::channel(DNS_EVENT_CHANNEL_SIZE);
    let (route_service_tx, route_service_rx) = mpsc::channel(ROUTE_EVENT_CHANNEL_SIZE);
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
        .await
    );

    let flow_rule_service = startup_phase!(
        "flow_rule_service.new",
        FlowRuleService::new(
            db_store_provider.clone(),
            dns_service_tx.clone(),
            route_service_tx.clone(),
            event_handle.subscribe_device(),
        )
        .await
    );

    let dns_redirect_service = startup_phase!(
        "dns_redirect_service.new",
        DNSRedirectService::new(db_store_provider.clone(), dns_service_tx.clone()).await
    );

    let metric_service = startup_phase!(
        "metric_service.new",
        MetricService::new(home_path.clone(), config.metric.clone()).await
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
        return Err(landscape_common::error::LdError::ConfigError(format!(
            "failed to load api tls certificates: {e}"
        )));
    }
    log_startup_phase("cert_service.reload_api_tls_mapping", phase_start, startup_start);
    #[cfg(feature = "gateway")]
    let gateway_tls_config = {
        let phase_start = Instant::now();
        let gateway_tls_mapping_count = match cert_service.reload_gateway_tls_mapping().await {
            Ok(count) => count,
            Err(e) => {
                return Err(landscape_common::error::LdError::ConfigError(format!(
                    "failed to load gateway tls certificates: {e}"
                )));
            }
        };
        if gateway_tls_mapping_count == 0 {
            tracing::warn!(
                "No valid for_gateway certificate found; gateway HTTPS listener will start but reject TLS handshakes until a certificate is loaded"
            );
        }
        let mut gateway_server_config =
            build_tls_server_config_with_shared_resolver(cert_service.gateway_tls_resolver());
        gateway_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        log_startup_phase("cert_service.reload_gateway_tls_mapping", phase_start, startup_start);
        Some(GatewayTlsConfig::new(std::sync::Arc::new(gateway_server_config)))
    };
    #[cfg(not(feature = "gateway"))]
    let gateway_tls_config: Option<GatewayTlsConfig> = None;

    // Gateway
    let gateway_store = db_store_provider.gateway_http_upstream_store();
    let gateway_service = startup_phase!(
        "gateway_service.init_service",
        GatewayService::init_service(gateway_store, config.gateway.clone(), gateway_tls_config)
            .await
    );

    let route_service = IpRouteService::new(route_service_rx, db_store_provider.flow_rule_store());
    let enrolled_devices =
        db_store_provider.enrolled_device_store().list_all().await.map_err(|e| {
            landscape_common::error::LdError::ConfigError(format!(
                "failed to list enrolled devices: {e}"
            ))
        })?;
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
            metric_service.get_dns_metric_channel(),
            event_handle.subscribe_device(),
            enrolled_devices,
        )
        .await
    );
    let dns_provider_profile_service =
        DnsProviderProfileService::new(db_store_provider.clone()).await;
    let prefix_map = IAPrefixMap::new();

    let lan_ipv6_service = LanIPv6ManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        event_handle.subscribe_device(),
        route_service.clone(),
        prefix_map.clone(),
        event_handle.ipv6_prefix_broadcast_tx(),
        ipv6_assign_sender.clone(),
    )
    .await;
    let enrolled_ipv6_cache = lan_ipv6_service.get_device_ipv6_map().await;

    let ddns_service = DdnsService::new(
        db_store_provider.clone(),
        route_service.clone(),
        prefix_map.clone(),
        event_handle.subscribe_ipv6_assign(),
        event_handle.subscribe_ipv6_prefix(),
        enrolled_ipv6_cache,
    )
    .await;

    let geo_ip_service =
        GeoIpService::new(db_store_provider.clone(), dst_ip_service_tx.clone()).await;
    let dst_ip_rule_service = DstIpRuleService::new(
        db_store_provider.clone(),
        geo_ip_service.clone(),
        dst_ip_service_tx.subscribe(),
    )
    .await;
    let firewall_blacklist_service = FirewallBlacklistService::new(
        db_store_provider.clone(),
        geo_ip_service.clone(),
        dst_ip_service_tx.subscribe(),
    )
    .await;

    let config_service =
        LandscapeConfigService::new(config.clone(), db_store_provider.clone()).await;

    let ebpf_service = LandscapeEbpfService::new();

    let static_nat_mapping_config_service =
        StaticNatMappingService::new(db_store_provider.clone(), event_handle.subscribe_device())
            .await;

    let enrolled_device_service =
        EnrolledDeviceService::new(db_store_provider.clone(), device_sender).await;

    let route_lan_service = RouteLanServiceManagerService::new(
        db_store_provider.clone(),
        route_service.clone(),
        event_handle.subscribe_iface(),
    )
    .await;
    let route_wan_service = RouteWanServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
    )
    .await;

    let mss_clamp_service = MssClampServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
    )
    .await;

    let firewall_service = FirewallServiceManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
    )
    .await;

    let nat_service =
        NatServiceManagerService::new(db_store_provider.clone(), event_handle.subscribe_iface())
            .await;

    let wifi_service = WifiServiceManagerService::new(db_store_provider.clone()).await;

    let iface_config_service = IfaceManagerService::new(db_store_provider.clone()).await;

    let dhcp_v4_server_service = DHCPv4ServerManagerService::new(
        route_service.clone(),
        db_store_provider.clone(),
        cert_service.api_tls_resolver(),
        config.dns.clone(),
        event_handle.subscribe_iface(),
        ipv4_assign_sender,
        event_handle.subscribe_device(),
    )
    .await;

    let wan_ip_service = IfaceIpServiceManagerService::new(
        route_service.clone(),
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
    )
    .await;

    let docker_service = LandscapeDockerService::new(home_path.clone(), route_service.clone());

    let pppd_service =
        PPPDServiceConfigManagerService::new(db_store_provider.clone(), route_service.clone())
            .await;

    let ipv6_pd_service = DHCPv6ClientManagerService::new(
        db_store_provider.clone(),
        event_handle.subscribe_iface(),
        route_service.clone(),
        prefix_map.clone(),
        ipv6_prefix_sender.clone(),
    )
    .await;

    startup_phase!(
        "docker_service.start_to_listen_event",
        docker_service.start_to_listen_event().await
    );

    startup_phase!("metric_service.start_service", metric_service.start_service().await);
    let auth_share = Arc::new(ArcSwap::from_pointee(config.auth.clone()));
    let landscape_app_status = LandscapeApp {
        home_path: home_path.clone(),
        auth: auth_share.clone(),
        dns_service,
        ddns_service,
        dns_provider_profile_service,
        dns_rule_service,
        flow_rule_service,
        geo_site_service,
        firewall_blacklist_service,
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
        lan_ipv6_service,
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
        enrolled_device_service,
        // cert
        cert_account_service,
        cert_service: cert_service.clone(),
        // gateway
        gateway_service: gateway_service.clone(),
    };

    gateway::sync_gateway_dynamic_dns_redirects(&landscape_app_status).await;

    // 初始化结束
    let tls_config = build_tls_server_config_with_shared_resolver(cert_service.api_tls_resolver());
    landscape_common::sys_config::init_sysctl_setting();

    let addr = SocketAddr::from((config.web.address, config.web.https_port));
    // spawn a second server to redirect http requests to this server
    spawn_task(
        task_label::task::WEB_REDIRECT_HTTPS,
        redirect_https::redirect_http_to_https(config.web.clone()),
    );
    let web_root = config.web.web_root.clone();
    let service = (move || handle_404(web_root)).into_service();

    let serve_dir = ServeDir::new(&config.web.web_root).not_found_service(service);

    auth::output_sys_token(&config.auth).await;
    // Build OpenApiRouter for each domain, then split into plain Router + discard local spec
    let (interfaces_router, _) = openapi::build_interfaces_openapi_router().split_for_parts();
    let (system_router, _) = openapi::build_system_openapi_router().split_for_parts();
    let (services_router, _) = openapi::build_services_openapi_router().split_for_parts();
    let (dns_router, _) = openapi::build_dns_openapi_router().split_for_parts();
    let (firewall_router, _) = openapi::build_firewall_openapi_router().split_for_parts();
    let (flow_router, _) = openapi::build_flow_openapi_router().split_for_parts();
    let (nat_router, _) = openapi::build_nat_openapi_router().split_for_parts();
    let (geo_router, _) = openapi::build_geo_openapi_router().split_for_parts();
    let (devices_router, _) = openapi::build_devices_openapi_router().split_for_parts();
    let (cert_router, _) = openapi::build_cert_openapi_router().split_for_parts();
    let (docker_router, _) = openapi::build_docker_openapi_router().split_for_parts();
    let (metrics_router, _) = openapi::build_metrics_openapi_router().split_for_parts();
    let (gateway_router, _) = openapi::build_gateway_openapi_router().split_for_parts();
    let openapi = openapi::build_full_openapi_spec();

    // /system combines two routers with different state types:
    // - system_router (LandscapeApp state): /config/...
    // - sysinfo (WatchResource state): /info/...
    let system_combined = system_router
        .with_state(landscape_app_status.clone())
        .merge(system::info::get_sys_info_route());

    // /api/v1 — all authenticated HTTP routes (Bearer token)
    let v1_route = Router::new()
        .nest("/interfaces", interfaces_router)
        .nest("/services", services_router)
        .nest("/dns", dns_router)
        .nest("/firewall", firewall_router)
        .nest("/flow", flow_router)
        .nest("/nat", nat_router)
        .nest("/geo", geo_router)
        .nest("/devices", devices_router)
        .nest("/cert", cert_router)
        .nest("/docker", docker_router)
        .nest("/metrics", metrics_router)
        .nest("/gateway", gateway_router)
        .with_state(landscape_app_status.clone())
        .nest("/system", system_combined)
        .route_layer(axum::middleware::from_fn_with_state(auth_share.clone(), auth::auth_handler));

    // /api/ws — WebSocket routes (query string token auth)
    let ws_route = Router::new()
        .nest("/docker", websocket::docker_task::get_docker_images_socks_paths().await)
        .nest("/pty", websocket::web_pty::get_web_pty_socks_paths().await)
        .with_state(landscape_app_status.clone())
        .merge(dump::get_tump_router())
        .route_layer(axum::middleware::from_fn_with_state(
            auth_share.clone(),
            auth::auth_handler_from_query,
        ));

    let api_route = Router::new()
        .nest("/v1", v1_route)
        .nest("/ws", ws_route)
        .nest("/auth", auth::get_auth_route(auth_share))
        .merge(Scalar::with_url("/docs", openapi).custom_html(
            r#"<!doctype html>
<html>
<head>
    <title>Landscape API Docs</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <link rel="stylesheet" href="/scalar/style.css"/>
    <style>
        .home-btn {
            position: fixed;
            top: 12px;
            right: 24px;
            z-index: 9999;
            padding: 6px 16px;
            background: #3451b2;
            color: #fff;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            text-decoration: none;
            line-height: 1.5;
        }
        .home-btn:hover {
            background: #2c3e8f;
        }
    </style>
</head>
<body>
<a class="home-btn" href="/">Home</a>
<script
        id="api-reference"
        type="application/json">
    $spec
</script>
<script src="/scalar/standalone.js"></script>
</body>
</html>"#,
        ));
    let app = Router::new()
        .nest("/api", api_route)
        // .nest("/sock", sockets_route)
        .route("/foo", get(|| async { "Hi from /foo" }))
        .fallback_service(serve_dir)
        .layer(TraceLayer::new_for_http());

    let server_handle = axum_server::Handle::new();
    let server = axum_server::bind_rustls(addr, RustlsConfig::from_config(tls_config.into()))
        .handle(server_handle.clone())
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!("Server error: {e:?}");
            }
        }
        _ = shutdown_signal() => {
            tracing::info!("Initiating graceful shutdown...");
        }
    }

    server_handle.graceful_shutdown(Some(Duration::from_secs(10)));

    let shutdown_timeout = Duration::from_secs(30);
    tracing::info!("Stopping all services ({}s timeout)...", shutdown_timeout.as_secs());
    match tokio::time::timeout(shutdown_timeout, landscape_app_status.shutdown()).await {
        Ok(()) => tracing::info!("All services stopped successfully."),
        Err(_) => tracing::warn!("Shutdown timed out, some hooks may remain."),
    }

    tracing::info!("Landscape Router shutdown complete.");
    Ok(())
}

fn main() -> LdResult<()> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .thread_name_fn(runtime_thread_name_fn(thread_name::prefix::CORE_RUNTIME))
        .build()
        .expect("failed to create main runtime");

    runtime.block_on(async_main())
}

async fn async_main() -> LdResult<()> {
    let home_path = LAND_HOME_PATH.clone();

    let lock_exists = home_path.join(landscape_common::INIT_LOCK_FILE_NAME).exists();
    let init_exists = home_path.join(landscape_common::INIT_FILE_NAME).exists();
    let db_exists = home_path.join(landscape_common::LANDSCAPE_DB_SQLITE_NAME).exists();

    let args = (*LAND_ARGS).clone();
    let init_config_to_import = if args.action.is_none() { boot_check(&home_path)? } else { None };
    let config = RuntimeConfig::new_with_file_config(
        args.clone(),
        init_config_to_import
            .as_ref()
            .filter(|_| init_exists)
            .map(|init_config| init_config.config.clone()),
    );

    if let Err(e) = init_logger(config.log.clone()) {
        panic!("init log error: {e:?}");
    }

    landscape_common::utils::time::start_time_sync_service(config.time.clone());

    let mut init_config_to_import = init_config_to_import;
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
            init_config_to_import = None;
        }
    }

    banner(&config);

    if let Some(action) = &args.action {
        match action {
            LandscapeAction::Db { action, rollback, times } => match action {
                Some(DbAction::Rollback) => {
                    landscape_database::provider::rollback_interactive(&config.store).await
                }
                None if *rollback || times.is_some() => {
                    tracing::warn!(
                        "Using deprecated step-based database action. Prefer `landscape db rollback`."
                    );
                    landscape_database::provider::db_action(
                        &config.store,
                        rollback,
                        &times.unwrap_or(1),
                    )
                    .await
                }
                None => {
                    eprintln!(
                        "No database action selected. Use `landscape db rollback` for interactive rollback."
                    );
                    Ok(())
                }
            },
        }
    } else {
        let db_store_provider =
            prepare_startup_init(&home_path, &config, init_config_to_import).await?;
        run_system(home_path, config, db_store_provider).await
    }
}

async fn do_auto_init(home_path: &PathBuf, config: &RuntimeConfig) -> LdResult<()> {
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
    write_init_lock(home_path)?;

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

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    // Ctrl+C (SIGINT)
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
        tracing::info!("Received SIGINT (Ctrl+C)");
    };

    // systemctl stop (SIGTERM)
    let terminate = async {
        signal(SignalKind::terminate()).expect("failed to install SIGTERM handler").recv().await;
        tracing::info!("Received SIGTERM (systemctl stop)");
    };

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received, starting graceful cleanup...");
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
