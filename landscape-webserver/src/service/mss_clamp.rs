use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::mss_clamp::MSSClampServiceConfig;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_mss_clamp_service_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_iface_service_status))
        .routes(routes!(handle_service_config))
        .routes(routes!(get_iface_service_conifg, delete_and_stop_iface_service))
}

#[utoipa::path(
    get,
    path = "/mss_clamp/status",
    tag = "MSS Clamp",
    operation_id = "get_all_mss_clamp_service_status",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, ServiceStatus>>)))
)]
async fn get_all_iface_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.mss_clamp_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/mss_clamp/{iface_name}",
    tag = "MSS Clamp",
    operation_id = "get_mss_clamp_service_config",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = inline(CommonApiResp<MSSClampServiceConfig>)),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    post,
    path = "/mss_clamp",
    tag = "MSS Clamp",
    operation_id = "handle_mss_clamp_service_config",
    request_body = MSSClampServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_service_config(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<MSSClampServiceConfig>,
) -> LandscapeApiResult<()> {
    state.mss_clamp_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/mss_clamp/{iface_name}",
    tag = "MSS Clamp",
    operation_id = "delete_and_stop_mss_clamp_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<ServiceStatus>>)))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(
        state.mss_clamp_service.delete_and_stop_iface_service(iface_name).await,
    )
}
