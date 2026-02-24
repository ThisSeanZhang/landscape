use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::route_wan::RouteWanServiceConfig;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_route_wan_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_route_wan_status))
        .routes(routes!(handle_route_wan_status))
        .routes(routes!(get_route_wan_conifg, delete_and_stop_route_wan))
}

#[utoipa::path(
    get,
    path = "/route_wans/status",
    tag = "Route WAN",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, ServiceStatus>>)))
)]
async fn get_all_route_wan_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.route_wan_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/route_wans/{iface_name}",
    tag = "Route WAN",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = inline(CommonApiResp<RouteWanServiceConfig>)),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    post,
    path = "/route_wans",
    tag = "Route WAN",
    request_body = RouteWanServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_route_wan_status(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<RouteWanServiceConfig>,
) -> LandscapeApiResult<()> {
    state.route_wan_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/route_wans/{iface_name}",
    tag = "Route WAN",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<ServiceStatus>>)))
)]
async fn delete_and_stop_route_wan(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(
        state.route_wan_service.delete_and_stop_iface_service(iface_name).await,
    )
}
