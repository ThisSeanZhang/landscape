use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::wan_service::firewall::service::FirewallServiceConfig;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_firewall_service_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_iface_service_status))
        .routes(routes!(handle_service_config))
        .routes(routes!(get_iface_service_config, delete_and_stop_iface_service))
}

#[utoipa::path(
    get,
    path = "/firewall/status",
    tag = "Firewall Service",
    operation_id = "get_all_firewall_service_status",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_iface_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, WatchService>> {
    LandscapeApiResp::success(state.firewall_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/firewall/{iface_name}",
    tag = "Firewall Service",
    operation_id = "get_firewall_service_config",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<FirewallServiceConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_service_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<FirewallServiceConfig> {
    if let Some(iface_config) = state.firewall_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Firewall" })?
    }
}

#[utoipa::path(
    put,
    path = "/firewall",
    tag = "Firewall Service",
    operation_id = "handle_firewall_service_config",
    request_body = FirewallServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_service_config(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<FirewallServiceConfig>,
) -> LandscapeApiResult<()> {
    state.validate_zone(&config).await?;
    state.firewall_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/firewall/{iface_name}",
    tag = "Firewall Service",
    operation_id = "delete_and_stop_firewall_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success", body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<WatchService>> {
    LandscapeApiResp::success(
        state.firewall_service.delete_and_stop_iface_service(iface_name).await,
    )
}
