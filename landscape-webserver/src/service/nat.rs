use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::{config::nat::NatServiceConfig, service::DefaultWatchServiceStatus};

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_iface_nat_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/nats/status", get(get_all_nat_status))
        .route("/nats", post(handle_iface_nat_status))
        .route("/nats/{iface_name}", get(get_iface_nat_conifg).delete(delete_and_stop_iface_nat))
    // .route("/nats/{iface_name}/restart", post(restart_nat_service_status))
}

async fn get_all_nat_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.nat_service.get_all_status().await)
}

async fn get_iface_nat_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<NatServiceConfig> {
    if let Some(iface_config) = state.nat_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Nat" })?
    }
}

async fn handle_iface_nat_status(
    State(state): State<LandscapeApp>,
    Json(config): Json<NatServiceConfig>,
) -> LandscapeApiResult<()> {
    state.nat_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_nat(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.nat_service.delete_and_stop_iface_service(iface_name).await)
}
