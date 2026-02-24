use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::dhcp::v6_client::config::IPV6PDServiceConfig;
use landscape_common::ipv6_pd::LDIAPrefix;
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_iface_pdclient_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_status))
        .routes(routes!(get_current_ip_prefix_info))
        .routes(routes!(handle_iface_pd))
        .routes(routes!(get_iface_pd_config, delete_and_stop_iface_service))
}

#[utoipa::path(
    get,
    path = "/ipv6pd/infos",
    tag = "IPv6 PD",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, Option<LDIAPrefix>>>)))
)]
async fn get_current_ip_prefix_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, Option<LDIAPrefix>>> {
    LandscapeApiResp::success(state.ipv6_pd_service.get_ipv6_prefix_infos().await)
}

#[utoipa::path(
    get,
    path = "/ipv6pd/status",
    tag = "IPv6 PD",
    operation_id = "get_all_ipv6pd_status",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, ServiceStatus>>)))
)]
async fn get_all_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.ipv6_pd_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/ipv6pd/{iface_name}",
    tag = "IPv6 PD",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = inline(CommonApiResp<IPV6PDServiceConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_pd_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<IPV6PDServiceConfig> {
    if let Some(iface_config) = state.ipv6_pd_service.get_config_by_name(iface_name).await {
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
    state.ipv6_pd_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/ipv6pd/{iface_name}",
    tag = "IPv6 PD",
    operation_id = "delete_and_stop_ipv6pd_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<ServiceStatus>>)))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.ipv6_pd_service.delete_and_stop_iface_service(iface_name).await)
}
