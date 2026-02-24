use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ppp::PPPDServiceConfig;
use landscape_common::database::LandscapeDBTrait;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_iface_pppd_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_pppd_configs, handle_iface_pppd_config))
        .routes(routes!(get_iface_pppd_conifg, delete_and_stop_iface_pppd))
        .routes(routes!(get_all_pppd_status))
        .routes(routes!(
            get_iface_pppd_conifg_by_attach_iface_name,
            delete_and_stop_iface_pppd_by_attach_iface_name
        ))
}

#[utoipa::path(
    get,
    path = "/pppds",
    tag = "PPPoE",
    responses((status = 200, body = inline(CommonApiResp<Vec<PPPDServiceConfig>>)))
)]
async fn get_all_pppd_configs(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<PPPDServiceConfig>> {
    LandscapeApiResp::success(state.pppd_service.get_repository().list().await.unwrap_or_default())
}

#[utoipa::path(
    get,
    path = "/pppds/status",
    tag = "PPPoE",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, ServiceStatus>>)))
)]
async fn get_all_pppd_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.pppd_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/pppds/attach/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Attach interface name")),
    responses((status = 200, body = inline(CommonApiResp<Vec<PPPDServiceConfig>>)))
)]
async fn get_iface_pppd_conifg_by_attach_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Vec<PPPDServiceConfig>> {
    let configs = state.pppd_service.get_pppd_configs_by_attach_iface_name(iface_name).await;

    LandscapeApiResp::success(configs)
}

#[utoipa::path(
    get,
    path = "/pppds/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = inline(CommonApiResp<PPPDServiceConfig>)),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    post,
    path = "/pppds",
    tag = "PPPoE",
    request_body = PPPDServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_iface_pppd_config(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<PPPDServiceConfig>,
) -> LandscapeApiResult<()> {
    state.pppd_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/pppds/attach/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Attach interface name")),
    responses((status = 200, description = "Success"))
)]
async fn delete_and_stop_iface_pppd_by_attach_iface_name(
    State(state): State<LandscapeApp>,
    Path(attach_name): Path<String>,
) -> LandscapeApiResult<()> {
    state.pppd_service.stop_pppds_by_attach_iface_name(attach_name).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/pppds/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<ServiceStatus>>)))
)]
async fn delete_and_stop_iface_pppd(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.pppd_service.delete_and_stop_iface_service(iface_name).await)
}
