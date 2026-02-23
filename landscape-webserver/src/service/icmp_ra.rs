use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::DefaultWatchServiceStatus;
use landscape_common::{config::ra::IPV6RAServiceConfig, lan_services::ipv6_ra::IPv6NAInfo};

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_iface_icmpv6ra_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/icmpv6ra/status", get(get_all_status))
        .route("/icmpv6ra", post(handle_iface_icmpv6))
        .route(
            "/icmpv6ra/{iface_name}",
            get(get_iface_icmpv6_conifg).delete(delete_and_stop_iface_icmpv6),
        )
        .route("/icmpv6ra/{iface_name}/assigned_ips", get(get_assigned_ips_by_iface_name))
        .route("/icmpv6ra/assigned_ips", get(get_all_iface_assigned_ips))
    // .route("/nats/{iface_name}/restart", post(restart_nat_service_status))
}

async fn get_all_iface_assigned_ips(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, IPv6NAInfo>> {
    LandscapeApiResp::success(state.ipv6_ra_service.get_assigned_ips().await)
}

async fn get_assigned_ips_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<IPv6NAInfo>> {
    LandscapeApiResp::success(
        state.ipv6_ra_service.get_assigned_ips_by_iface_name(iface_name).await,
    )
}

async fn get_all_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.ipv6_ra_service.get_all_status().await)
}

async fn get_iface_icmpv6_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<IPV6RAServiceConfig> {
    if let Some(iface_config) = state.ipv6_ra_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "IPv6 RA" })?
    }
}

async fn handle_iface_icmpv6(
    State(state): State<LandscapeApp>,
    Json(config): Json<IPV6RAServiceConfig>,
) -> LandscapeApiResult<()> {
    state.ipv6_ra_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_icmpv6(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.ipv6_ra_service.delete_and_stop_iface_service(iface_name).await)
}
