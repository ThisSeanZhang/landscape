use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::route_lan::RouteLanServiceConfig;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_route_lan_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_route_lan_status))
        .routes(routes!(handle_route_lan_status))
        .routes(routes!(get_route_lan_config, delete_and_stop_route_lan))
}

#[utoipa::path(
    get,
    path = "/lan/status",
    tag = "Route LAN",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, ServiceStatus>>)))
)]
async fn get_all_route_lan_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.route_lan_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/lan/{iface_name}",
    tag = "Route LAN",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = inline(CommonApiResp<RouteLanServiceConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_route_lan_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<RouteLanServiceConfig> {
    if let Some(iface_config) = state.route_lan_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Route Lan" })?
    }
}

#[utoipa::path(
    put,
    path = "/lan",
    tag = "Route LAN",
    request_body = RouteLanServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_route_lan_status(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<RouteLanServiceConfig>,
) -> LandscapeApiResult<()> {
    state.route_lan_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/lan/{iface_name}",
    tag = "Route LAN",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<ServiceStatus>>)))
)]
async fn delete_and_stop_route_lan(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(
        state.route_lan_service.delete_and_stop_iface_service(iface_name).await,
    )
}
