use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};

use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::{config::wifi::WifiServiceConfig, service::DefaultWatchServiceStatus};

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_wifi_service_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/wifi/status", get(get_all_iface_service_status))
        .route("/wifi", post(handle_service_config))
        .route(
            "/wifi/{iface_name}",
            get(get_iface_service_conifg).delete(delete_and_stop_iface_service),
        )
}

async fn get_all_iface_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.wifi_service.get_all_status().await)
}

async fn get_iface_service_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<WifiServiceConfig> {
    if let Some(iface_config) = state.wifi_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Wifi" })?
    }
}

async fn handle_service_config(
    State(state): State<LandscapeApp>,
    Json(config): Json<WifiServiceConfig>,
) -> LandscapeApiResult<()> {
    state.wifi_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.wifi_service.delete_and_stop_iface_service(iface_name).await)
}
