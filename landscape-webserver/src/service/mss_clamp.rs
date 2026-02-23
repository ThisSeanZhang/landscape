use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::controller_service_v2::ControllerService;

use landscape_common::{
    config::mss_clamp::MSSClampServiceConfig, service::DefaultWatchServiceStatus,
};

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_mss_clamp_service_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/mss_clamp/status", get(get_all_iface_service_status))
        .route("/mss_clamp", post(handle_service_config))
        .route(
            "/mss_clamp/{iface_name}",
            get(get_iface_service_conifg).delete(delete_and_stop_iface_service),
        )
    // .route("/mss_clamp/{iface_name}/restart", post(restart_mark_service_status))
}

async fn get_all_iface_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.mss_clamp_service.get_all_status().await)
}

async fn get_iface_service_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<MSSClampServiceConfig> {
    if let Some(iface_config) = state.mss_clamp_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "MSS Clamp" })?
    }
}

async fn handle_service_config(
    State(state): State<LandscapeApp>,
    Json(config): Json<MSSClampServiceConfig>,
) -> LandscapeApiResult<()> {
    state.mss_clamp_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(
        state.mss_clamp_service.delete_and_stop_iface_service(iface_name).await,
    )
}
