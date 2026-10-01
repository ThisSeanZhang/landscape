use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::lan_service::lan_dhcpv4::config::DHCPv4ServiceConfig;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::ConfigStoreServiceController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::lan_service::lan_dhcpv4::DhcpError;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dhcp_v4_service_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_iface_service_status))
        .routes(routes!(handle_service_config))
        .routes(routes!(get_iface_service_config, delete_and_stop_iface_service))
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/status",
    tag = "DHCPv4",
    operation_id = "get_all_dhcp_v4_service_status",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_iface_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, ServiceStatus>> {
    LandscapeApiResp::success(state.dhcp_v4_server_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/{iface_name}",
    tag = "DHCPv4",
    operation_id = "get_dhcp_v4_service_config",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<DHCPv4ServiceConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_service_config(
    State(state): State<LandscapeApp>,
    Path(service_name): Path<String>,
) -> LandscapeApiResult<DHCPv4ServiceConfig> {
    if let Some(iface_config) =
        state.dhcp_v4_server_service.get_config_by_name(service_name.clone()).await
    {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(DhcpError::ConfigNotFound { id: service_name })?
    }
}

#[utoipa::path(
    put,
    path = "/dhcp_v4",
    tag = "DHCPv4",
    operation_id = "handle_dhcp_v4_service_config",
    request_body = DHCPv4ServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_service_config(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<DHCPv4ServiceConfig>,
) -> LandscapeApiResult<()> {
    state.dhcp_v4_server_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/dhcp_v4/{iface_name}",
    tag = "DHCPv4",
    operation_id = "delete_and_stop_dhcp_v4_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success", body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<ServiceStatus>> {
    LandscapeApiResp::success(
        state.dhcp_v4_server_service.delete_and_stop_service(iface_name).await?,
    )
}
