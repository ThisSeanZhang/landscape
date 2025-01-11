use std::net::SocketAddr;

use axum::{handler::HandlerWithoutStateExt, http::StatusCode, routing::get, Router};

use landscape_common::args::LAND_ARGS;
use serde::{Deserialize, Serialize};
use tower_http::{services::ServeDir, trace::TraceLayer};

mod docker;
mod dump;
mod error;
mod iface;
mod service;
mod sysinfo;

#[derive(Clone, Serialize, Deserialize)]
struct SimpleResult {
    success: bool,
}

#[tokio::main]
async fn main() {
    let args = LAND_ARGS.clone();
    println!("test: {args:?}");

    let addr = SocketAddr::from((args.address, args.port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    let service = handle_404.into_service();
    let serve_dir = ServeDir::new(&args.web).not_found_service(service);

    let home_path = homedir::my_home().unwrap().unwrap().join(".landscape-router");

    let api_route = Router::new()
        .nest("/docker", docker::get_docker_paths(home_path.clone()).await)
        .nest("/iface", iface::get_network_paths(home_path.clone()).await)
        .nest("/services", service::get_service_paths(home_path).await)
        .nest("/sysinfo", sysinfo::get_sys_info_route());
    // sysinfo::get_sys_info_route().merge(bridge::get_bridge_route());
    let app = Router::new()
        .nest("/api", api_route)
        .nest("/sock", dump::get_tump_router())
        .route("/foo", get(|| async { "Hi from /foo" }))
        .fallback_service(serve_dir);

    axum::serve(listener, app.layer(TraceLayer::new_for_http())).await.unwrap();
}

/// NOT Found
async fn handle_404() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}
