use std::net::SocketAddr;

use axum::{
    handler::HandlerWithoutStateExt,
    http::StatusCode,
    routing::{get, post},
    Router,
};

use landscape::boot::{boot_check, init_ports, InitConfig};
use landscape_common::{
    args::{LAND_ARGS, LAND_HOME_PATH, LAND_WEB_ARGS},
    error::LdResult,
    store::storev2::StoreFileManager,
};
use serde::{Deserialize, Serialize};
use tower_http::{services::ServeDir, trace::TraceLayer};

mod auth;
mod dns;
mod docker;
mod dump;
mod error;
mod global_mark;
mod iface;
mod service;
mod sysinfo;

use service::ipconfig::get_iface_ipconfig_paths;
use service::nat::get_iface_nat_paths;
use service::packet_mark::get_iface_packet_mark_paths;
use service::pppd::get_iface_pppd_paths;

#[derive(Clone, Serialize, Deserialize)]
struct SimpleResult {
    success: bool,
}

#[tokio::main]
async fn main() -> LdResult<()> {
    let args = LAND_ARGS.clone();
    println!("using args: {args:?}");
    init_ports();
    let home_path = LAND_HOME_PATH.clone();

    println!("config path: {home_path:?}");

    let dev_obs = landscape::observer::dev_observer().await;
    let mut iface_store = StoreFileManager::new(home_path.clone(), "iface".to_string());
    let mut iface_ipconfig_store =
        StoreFileManager::new(home_path.clone(), "iface_ipconfig".to_string());
    let mut iface_nat_store = StoreFileManager::new(home_path.clone(), "iface_nat".to_string());

    let mut iface_mark_store = StoreFileManager::new(home_path.clone(), "iface_mark".to_string());

    let mut iface_pppd_store = StoreFileManager::new(home_path.clone(), "iface_pppd".to_string());

    let mut dns_store = StoreFileManager::new(home_path.clone(), "dns_rule".to_string());

    let mut lan_ip_mark_store = StoreFileManager::new(home_path.clone(), "lan_ip_mark".to_string());

    let mut wan_ip_mark_store = StoreFileManager::new(home_path.clone(), "wan_ip_mark".to_string());

    let need_init_config = boot_check(&home_path)?;

    println!("init config: {need_init_config:?}");

    if let Some(InitConfig {
        ifaces,
        ipconfigs,
        nats,
        marks,
        pppds,
        dns_rules,
        lan_ip_mark,
        wan_ip_mark,
    }) = need_init_config
    {
        iface_store.truncate();
        iface_ipconfig_store.truncate();
        iface_nat_store.truncate();
        iface_mark_store.truncate();
        iface_pppd_store.truncate();
        dns_store.truncate();
        lan_ip_mark_store.truncate();
        wan_ip_mark_store.truncate();

        for each_config in ifaces {
            iface_store.set(each_config);
        }

        for each_config in ipconfigs {
            iface_ipconfig_store.set(each_config);
        }

        for each_config in nats {
            iface_nat_store.set(each_config);
        }

        for each_config in marks {
            iface_mark_store.set(each_config);
        }

        for each_config in pppds {
            iface_pppd_store.set(each_config);
        }

        for each_config in dns_rules {
            dns_store.set(each_config);
        }

        for each_config in lan_ip_mark {
            lan_ip_mark_store.set(each_config);
        }

        for each_config in wan_ip_mark {
            wan_ip_mark_store.set(each_config);
        }
    }

    // need iproute2
    if let Err(e) =
        std::process::Command::new("iptables").args(["-A", "FORWARD", "-j", "ACCEPT"]).output()
    {
        println!("iptables cmd exec err: {e:?}");
    }

    // need procps
    if let Err(e) =
        std::process::Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output()
    {
        println!("sysctl cmd exec err: {e:?}");
    }

    let addr = SocketAddr::from((LAND_WEB_ARGS.address, LAND_WEB_ARGS.port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    // let _ = landscape_dns::connection::set_socket_mark(
    //     std::os::fd::AsFd::as_fd(&listener).as_raw_fd(),
    //     landscape_common::mark::PacketMark::LandscapeSys.into(),
    // )
    // .unwrap();

    let service = handle_404.into_service();
    let serve_dir = ServeDir::new(&LAND_WEB_ARGS.web_root).not_found_service(service);

    let source_route = Router::new()
        .nest("/docker", docker::get_docker_paths(home_path.clone()).await)
        .nest("/iface", iface::get_network_paths(iface_store).await)
        .nest(
            "/global_mark",
            global_mark::get_global_mark_paths(lan_ip_mark_store, wan_ip_mark_store).await,
        )
        .nest("/dns", dns::get_dns_paths(dns_store).await)
        .nest(
            "/services",
            Router::new()
                .merge(get_iface_ipconfig_paths(iface_ipconfig_store).await)
                .merge(get_iface_pppd_paths(iface_pppd_store).await)
                .merge(get_iface_nat_paths(iface_nat_store, dev_obs.resubscribe()).await)
                .merge(get_iface_packet_mark_paths(iface_mark_store, dev_obs).await),
        )
        .nest("/sysinfo", sysinfo::get_sys_info_route())
        .route_layer(axum::middleware::from_fn(auth::auth_middleware));

    let auth_route = Router::new().route("/login", post(auth::login_handler));
    let api_route = Router::new()
        // 资源路由
        .nest("/src", source_route)
        // 认证路由
        .nest("/auth", auth_route);
    let app = Router::new()
        .nest("/api", api_route)
        .nest("/sock", dump::get_tump_router())
        .route("/foo", get(|| async { "Hi from /foo" }))
        .fallback_service(serve_dir);

    axum::serve(listener, app.layer(TraceLayer::new_for_http())).await.unwrap();
    Ok(())
}

/// NOT Found
async fn handle_404() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}
