use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use landscape_common::database::LandscapeDBTrait;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::{config::ppp::PPPDServiceConfig, service::DefaultWatchServiceStatus};

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_iface_pppd_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/pppds", get(get_all_pppd_configs).post(handle_iface_pppd_config))
        .route("/pppds/{iface_name}", get(get_iface_pppd_conifg).delete(delete_and_stop_iface_pppd))
        .route("/pppds/status", get(get_all_pppd_status))
        .route(
            "/pppds/attach/{iface_name}",
            get(get_iface_pppd_conifg_by_attach_iface_name)
                .delete(delete_and_stop_iface_pppd_by_attach_iface_name),
        )
}

async fn get_all_pppd_configs(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<PPPDServiceConfig>> {
    LandscapeApiResp::success(state.pppd_service.get_repository().list().await.unwrap_or_default())
}

async fn get_all_pppd_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.pppd_service.get_all_status().await)
}

async fn get_iface_pppd_conifg_by_attach_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Vec<PPPDServiceConfig>> {
    let configs = state.pppd_service.get_pppd_configs_by_attach_iface_name(iface_name).await;

    LandscapeApiResp::success(configs)
}

async fn get_iface_pppd_conifg(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<PPPDServiceConfig> {
    if let Some(iface_config) = state.pppd_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "PPPD" })?
    }
}

async fn handle_iface_pppd_config(
    State(state): State<LandscapeApp>,
    Json(config): Json<PPPDServiceConfig>,
) -> LandscapeApiResult<()> {
    state.pppd_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_pppd_by_attach_iface_name(
    State(state): State<LandscapeApp>,
    Path(attach_name): Path<String>,
) -> LandscapeApiResult<()> {
    state.pppd_service.stop_pppds_by_attach_iface_name(attach_name).await;
    LandscapeApiResp::success(())
}

async fn delete_and_stop_iface_pppd(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.pppd_service.delete_and_stop_iface_service(iface_name).await)
}
