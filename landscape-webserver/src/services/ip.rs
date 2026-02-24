use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::iface_ip::IfaceIpServiceConfig;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_iface_ipconfig_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_ipconfig_status))
        .routes(routes!(handle_iface_service_status))
        .routes(routes!(get_iface_service_config, delete_and_stop_iface_service))
}

#[utoipa::path(
    get,
    path = "/ip/status",
    tag = "IP Config",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, ServiceStatus>>)))
)]
async fn get_all_ipconfig_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.wan_ip_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/ip/{iface_name}",
    tag = "IP Config",
    operation_id = "get_ipconfig_service_config",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = inline(CommonApiResp<IfaceIpServiceConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_service_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<IfaceIpServiceConfig> {
    if let Some(iface_config) = state.wan_ip_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Iface Ip" })?
    }
}

#[utoipa::path(
    put,
    path = "/ip",
    tag = "IP Config",
    request_body = IfaceIpServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_iface_service_status(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<IfaceIpServiceConfig>,
) -> LandscapeApiResult<()> {
    state.wan_ip_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/ip/{iface_name}",
    tag = "IP Config",
    operation_id = "delete_and_stop_ipconfig_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<ServiceStatus>>)))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.wan_ip_service.delete_and_stop_iface_service(iface_name).await)
}
