use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::DefaultWatchServiceStatus;
use landscape_common::{
    config::route_wan::RouteWanServiceConfig, service::controller_service_v2::ControllerService,
};

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_route_wan_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/route_wans/status", get(get_all_route_wan_status))
        .route("/route_wans", post(handle_route_wan_status))
        .route(
            "/route_wans/{iface_name}",
            get(get_route_wan_conifg).delete(delete_and_stop_route_wan),
        )
}

async fn get_all_route_wan_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.route_wan_service.get_all_status().await)
}

async fn get_route_wan_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<RouteWanServiceConfig> {
    if let Some(iface_config) = state.route_wan_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Route Wan" })?
    }
}

async fn handle_route_wan_status(
    State(state): State<LandscapeApp>,
    Json(config): Json<RouteWanServiceConfig>,
) -> LandscapeApiResult<()> {
    state.route_wan_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_route_wan(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(
        state.route_wan_service.delete_and_stop_iface_service(iface_name).await,
    )
}
