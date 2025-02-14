use std::net::SocketAddr;

use axum::{handler::HandlerWithoutStateExt, http::StatusCode, routing::get, Router};

use landscape::boot::{boot_check, InitConfig};
use landscape_common::{
    args::LAND_ARGS,
    error::{LdError, LdResult},
    store::storev2::StoreFileManager,
    LANDSCAPE_CONFIG_DIR_NAME,
};
use serde::{Deserialize, Serialize};
use tower_http::{services::ServeDir, trace::TraceLayer};

mod dns;
mod docker;
mod dump;
mod error;
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

    let home_path = if let Some(path) = &args.config_path {
        path.clone()
    } else {
        let Some(path) = homedir::my_home()? else {
            return Err(LdError::Boot("can not get home path".to_string()));
        };
        path.join(LANDSCAPE_CONFIG_DIR_NAME)
    };

    println!("config path: {home_path:?}");

    let mut iface_store = StoreFileManager::new(home_path.clone(), "iface".to_string());

    let need_init_config = boot_check(&home_path)?;

    if let Some(InitConfig { ifaces, ipconfigs, nats, marks, pppds }) = need_init_config {
        iface_store.truncate();
        for iface_config in ifaces {
            iface_store.set(iface_config);
        }
    }

    // need iproute2
    std::process::Command::new("iptables")
        .args(["-A", "FORWARD", "-j", "ACCEPT"])
        .output()
        .unwrap();

    // need procps
    std::process::Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).output().unwrap();

    let addr = SocketAddr::from((args.address, args.port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let service = handle_404.into_service();
    let serve_dir = ServeDir::new(&args.web).not_found_service(service);

    let api_route = Router::new()
        .nest("/docker", docker::get_docker_paths(home_path.clone()).await)
        .nest("/iface", iface::get_network_paths(iface_store).await)
        .nest("/dns", dns::get_dns_paths(home_path.clone()).await)
        .nest(
            "/services",
            Router::new()
                .merge(get_iface_ipconfig_paths(home_path.clone()).await)
                .merge(get_iface_pppd_paths(home_path.clone()).await)
                .merge(get_iface_packet_mark_paths(home_path.clone()).await)
                .merge(get_iface_nat_paths(home_path.clone()).await),
        )
        .nest("/sysinfo", sysinfo::get_sys_info_route());
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
