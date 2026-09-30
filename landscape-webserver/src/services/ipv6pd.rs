use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::wan_service::ipv6_pd::IPV6PDPrefixStatus;
use landscape_common::wan_service::ipv6_pd::IPV6PDServiceConfig;
use landscape_common::wan_service::ipv6_pd::LDIAPrefix;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_iface_pdclient_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_status))
        .routes(routes!(get_all_ipv6pd_configs))
        .routes(routes!(get_current_ip_prefix_info))
        .routes(routes!(get_all_prefix_status))
        .routes(routes!(handle_iface_pd))
        .routes(routes!(get_iface_pd_config, delete_and_stop_iface_service))
}

#[utoipa::path(
    get,
    path = "/ipv6pd",
    tag = "IPv6 PD",
    operation_id = "get_all_ipv6pd_configs",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<IPV6PDServiceConfig>>))
)]
async fn get_all_ipv6pd_configs(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IPV6PDServiceConfig>> {
    LandscapeApiResp::success(state.ipv6_pd_service.list().await.unwrap_or_default())
}

#[utoipa::path(
    get,
    path = "/ipv6pd/prefix-status",
    tag = "IPv6 PD",
    operation_id = "get_all_ipv6pd_prefix_status",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, IPV6PDPrefixStatus>>))
)]
async fn get_all_prefix_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, IPV6PDPrefixStatus>> {
    LandscapeApiResp::success(state.ipv6_pd_service.get_ipv6_prefix_statuses())
}

#[utoipa::path(
    get,
    path = "/ipv6pd/infos",
    tag = "IPv6 PD",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, Option<LDIAPrefix>>>))
)]
async fn get_current_ip_prefix_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, Option<LDIAPrefix>>> {
    LandscapeApiResp::success(state.ipv6_pd_service.get_ipv6_prefix_infos())
}

#[utoipa::path(
    get,
    path = "/ipv6pd/status",
    tag = "IPv6 PD",
    operation_id = "get_all_ipv6pd_status",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, ServiceStatus>> {
    LandscapeApiResp::success(state.ipv6_pd_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/ipv6pd/{iface_name}",
    tag = "IPv6 PD",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<IPV6PDServiceConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_pd_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<IPV6PDServiceConfig> {
    if let Some(iface_config) = state.ipv6_pd_service.find_by_id(iface_name).await? {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "IPV6PD" })?
    }
}

#[utoipa::path(
    put,
    path = "/ipv6pd",
    tag = "IPv6 PD",
    request_body = IPV6PDServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_iface_pd(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<IPV6PDServiceConfig>,
) -> LandscapeApiResult<()> {
    state.ipv6_pd_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/ipv6pd/{iface_name}",
    tag = "IPv6 PD",
    operation_id = "delete_and_stop_ipv6pd_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success", body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<ServiceStatus>> {
    LandscapeApiResp::success(state.ipv6_pd_service.delete_and_stop_service(iface_name).await?)
}
