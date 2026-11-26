use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axum::{
    Router, handler::HandlerWithoutStateExt, http::StatusCode, response::IntoResponse, routing::get,
};

use axum_server::tls_rustls::RustlsConfig;
use colored::Colorize;

use landscape::boot::{
    boot_check, log::init_logger, prepare_init_config_import, write_config_toml, write_init_lock,
};
use landscape_common::lan_service::lan_route::RouteLanServiceConfig;
use landscape_common::{
    VERSION,
    args::{DbAction, LAND_ARGS, LAND_HOME_PATH, LandscapeAction},
    concurrency::{runtime_thread_name_fn, spawn_task, task_label, thread_name},
    database::error::DbError,
    database::store::ConfigStore,
    sys_config::RuntimeConfig,
};
use landscape_common::{config::InitConfig, lan_service::lan_dhcpv4::config::DHCPv4ServiceConfig};
use landscape_core::cert::build_tls_server_config_with_shared_resolver;
use landscape_core::time::SyncTimeService;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::runtime::Builder as RuntimeBuilder;
use tower_http::{compression::CompressionLayer, services::ServeDir, trace::TraceLayer};
use utoipa_scalar::{Scalar, Servable};

mod api;
mod app;
mod auth;
mod bootstrap;
mod cert;
mod devices;
mod dns;
mod docker;
mod dump;
mod error;
mod firewall;
mod flow;
mod gateway;
mod geo;
mod interfaces;
mod metrics;
mod nat;
mod openapi;
mod redirect_https;
mod self_monitor;
mod services;
#[cfg(test)]
mod startup_tests;
mod system;
mod websocket;

pub use app::LandscapeApp;

use tracing::info;

const DNS_EVENT_CHANNEL_SIZE: usize = 128;
const DST_IP_EVENT_CHANNEL_SIZE: usize = 128;

const UPLOAD_GEO_FILE_SIZE_LIMIT: usize = 100 * 1024 * 1024;

/// 按子系统记账的全局分配器(feature `mem-track` 显式开启时精确归属;
/// 未开启时为 System 纯透传,零开销)。必须尽早声明,覆盖进程全部堆分配。
#[global_allocator]
static GLOBAL_ALLOCATOR: landscape_common::memtrack::CountingAllocator =
    landscape_common::memtrack::CountingAllocator;

fn log_startup_phase(phase: &str, phase_start: Instant, startup_start: Instant) {
    tracing::info!(
        "startup phase={} elapsed_ms={} since_run_ms={}",
        phase,
        phase_start.elapsed().as_millis(),
        startup_start.elapsed().as_millis()
    );
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error(transparent)]
    Boot(#[from] landscape::boot::BootError),
    #[error(transparent)]
    Database(#[from] DbError),
    #[error(transparent)]
    InitConfig(#[from] landscape_common::config::InitConfigError),
    #[error("{0}")]
    Cert(String),
    #[error("previous metric service is still stopping: {0}")]
    MetricStop(#[from] tokio::time::error::Elapsed),
    #[error("config: {0}")]
    Config(String),
}

async fn prepare_startup_init(
    home_path: &Path,
    config: &RuntimeConfig,
    init_config_to_import: Option<InitConfig>,
) -> Result<LandscapeDBServiceProvider, StartupError> {
    let startup_start = Instant::now();

    macro_rules! startup_phase {
        ($name:literal, $expr:expr) => {{
            let phase_start = Instant::now();
            let value = $expr;
            log_startup_phase($name, phase_start, startup_start);
            value
        }};
    }

    // Validate the same candidate as upload preflight, before opening the live
    // database or replacing any configuration files and initialization lock.
    let init_config_to_import = match init_config_to_import {
        Some(init_config) => Some(startup_phase!(
            "prepare_init_config_import",
            prepare_init_config_import(init_config).await?
        )),
        None => None,
    };
    let init_file_config_to_persist = init_config_to_import
        .as_ref()
        .filter(|init_config| !init_config.version.is_empty())
        .map(|init_config| init_config.config.clone());

    let crypto_provider = rustls::crypto::ring::default_provider();
    crypto_provider.install_default().unwrap();

    let db_store_provider = startup_phase!(
        "db_store_provider.new",
        LandscapeDBServiceProvider::new(&config.store).await?
    );

    if let Some(init_config) = init_config_to_import {
        startup_phase!("db_store_provider.truncate_and_fit_from", {
            db_store_provider
                .truncate_and_fit_from_before_commit(init_config, || {
                    if let Some(config) = init_file_config_to_persist {
                        write_config_toml(home_path, config)
                            .map_err(|e| DbError::Internal(e.to_string()))?;
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
    time_service: SyncTimeService,
) -> Result<(), StartupError> {
    let bootstrap =
        bootstrap::build_app(home_path, &config, db_store_provider, time_service).await?;
    let landscape_app_status = bootstrap.app;
    let auth_share = bootstrap.auth;
    let ebpf_paths = bootstrap.ebpf_paths;

    landscape_app_status.managed.gateway_rules.sync_dynamic_dns_redirects().await;

    // 初始化结束
    let tls_config = build_tls_server_config_with_shared_resolver(
        landscape_app_status.managed.cert_service.api_tls_resolver(),
    );
    landscape_common::utils::sysctl::init_sysctl_setting();

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
    let (self_monitor_router, _) = openapi::build_self_monitor_openapi_router().split_for_parts();
    let (gateway_router, _) = openapi::build_gateway_openapi_router().split_for_parts();
    let openapi = openapi::build_full_openapi_spec();

    // /system combines two routers with different state types:
    // - system_router (LandscapeApp state): /config/...
    // - sysinfo (shared status snapshot state): /info/...
    let system_combined = system_router
        .with_state(landscape_app_status.clone())
        .merge(system::info::get_sys_info_route(ebpf_paths.clone()));

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
        .nest("/self-monitor", self_monitor_router)
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
        .layer(CompressionLayer::new())
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

fn main() -> Result<(), StartupError> {
    let runtime = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .thread_name_fn(runtime_thread_name_fn(thread_name::prefix::CORE_RUNTIME))
        .build()
        .expect("failed to create main runtime");

    runtime.block_on(async_main())
}

async fn async_main() -> Result<(), StartupError> {
    let home_path = LAND_HOME_PATH.clone();

    let lock_exists = home_path.join(landscape_common::INIT_LOCK_FILE_NAME).exists();
    let init_exists = home_path.join(landscape_common::INIT_FILE_NAME).exists();
    let db_exists = home_path.join(landscape_common::LANDSCAPE_DB_SQLITE_NAME).exists();

    let args = (*LAND_ARGS).clone();

    // The `config` subcommand only generates a landscape_init.toml. It does not
    // touch the database, eBPF or the running system, so handle it before any
    // logging / time-sync side effects.
    if let Some(LandscapeAction::Config(config_args)) = &args.action {
        landscape_common::config::cli::run_config_cli(config_args)
            .map_err(|e| StartupError::Config(e.to_string()))?;
        return Ok(());
    }

    // Geo pipeline commands are pure file-to-file stages: they must not touch
    // the database, eBPF, logging or time sync. `geo build` also runs inside a
    // child process, so this branch is what that child executes.
    if let Some(LandscapeAction::Geo(geo)) = &args.action {
        return match landscape::geo::cli::run(&geo.action).await {
            Ok(()) => Ok(()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(error.exit_code().into());
            }
        };
    }

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

    let time_service = SyncTimeService::start(config.time.clone());

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
                    landscape_database::provider::rollback_interactive(&config.store)
                        .await
                        .map_err(StartupError::from)
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
                    .map_err(StartupError::from)
                }
                None => {
                    eprintln!(
                        "No database action selected. Use `landscape db rollback` for interactive rollback."
                    );
                    Ok(())
                }
            },
            // Handled (and returned early) before this point.
            LandscapeAction::Config(_) | LandscapeAction::Geo(_) => Ok(()),
        }
    } else {
        let db_store_provider =
            prepare_startup_init(&home_path, &config, init_config_to_import).await?;
        run_system(home_path, config, db_store_provider, time_service).await
    }
}

async fn do_auto_init(home_path: &PathBuf, config: &RuntimeConfig) -> Result<(), StartupError> {
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

    let db_store_provider = LandscapeDBServiceProvider::new(&config.store).await?;
    let store = db_store_provider.iface_store();
    for cfg in default_configs {
        store.upsert(cfg).await.unwrap();
    }

    // 创建 lock 文件 避免重复进行初始化
    write_init_lock(home_path)?;

    // 初始化 br_lan 的服务
    let dhcp_store = db_store_provider.dhcp_v4_server_store();
    dhcp_store.upsert(DHCPv4ServiceConfig::default()).await.unwrap();

    let route_lan_store = db_store_provider.route_lan_service_store();
    route_lan_store
        .upsert(RouteLanServiceConfig {
            iface_name: landscape_common::LANDSCAPE_DEFAULT_LAN_NAME.to_string(),
            enable: true,
            update_at: landscape_common::utils::time::get_f64_timestamp(),
            static_routes: None,
        })
        .await
        .unwrap();

    tracing::info!(
        "Auto init: bridge, IP, DHCP and Route services configuration saved to database."
    );
    Ok(())
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
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
    if path.exists()
        && let Ok(content) = std::fs::read_to_string(path)
    {
        return (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/html")], content)
            .into_response();
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
