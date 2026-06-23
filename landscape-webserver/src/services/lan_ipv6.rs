use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::dhcp::v6_server::status::DHCPv6OfferInfo;
use landscape_common::ipv6::lan::{
    validate_cross_interface_v2_with_prefix_infos, LanIPv6ServiceConfigV2,
};
use landscape_common::lan_services::ipv6_ra::IPv6NAInfo;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::{ServiceStatus, WatchService};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::database::LandscapeStore as LandscapeDBStore;
use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_lan_ipv6_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_status))
        .routes(routes!(get_all_lan_ipv6_configs))
        .routes(routes!(handle_lan_ipv6))
        .routes(routes!(get_lan_ipv6_config, delete_and_stop_lan_ipv6))
        .routes(routes!(get_assigned_ips_by_iface_name))
        .routes(routes!(get_all_iface_assigned_ips))
        .routes(routes!(get_dhcpv6_assigned_by_iface_name))
        .routes(routes!(get_all_dhcpv6_assigned))
}

#[utoipa::path(
    get,
    path = "/lan_ipv6/assigned_ips",
    tag = "LAN IPv6",
    operation_id = "get_all_lan_ipv6_assigned_ips",
    responses((status = 200, body = CommonApiResp<HashMap<String, IPv6NAInfo>>))
)]
async fn get_all_iface_assigned_ips(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, IPv6NAInfo>> {
    LandscapeApiResp::success(state.lan_ipv6_service.get_assigned_ips().await)
}

#[utoipa::path(
    get,
    path = "/lan_ipv6/{iface_name}/assigned_ips",
    tag = "LAN IPv6",
    operation_id = "get_lan_ipv6_assigned_ips_by_iface_name",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = CommonApiResp<Option<IPv6NAInfo>>))
)]
async fn get_assigned_ips_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<IPv6NAInfo>> {
    LandscapeApiResp::success(
        state.lan_ipv6_service.get_assigned_ips_by_iface_name(iface_name).await,
    )
}

#[utoipa::path(
    get,
    path = "/lan_ipv6/status",
    tag = "LAN IPv6",
    operation_id = "get_all_lan_ipv6_status",
    responses((status = 200, body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, WatchService>> {
    LandscapeApiResp::success(state.lan_ipv6_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/lan_ipv6",
    tag = "LAN IPv6",
    operation_id = "get_all_lan_ipv6_configs",
    responses((status = 200, body = CommonApiResp<Vec<LanIPv6ServiceConfigV2>>))
)]
async fn get_all_lan_ipv6_configs(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<LanIPv6ServiceConfigV2>> {
    LandscapeApiResp::success(
        state.lan_ipv6_service.get_repository().list().await.unwrap_or_default(),
    )
}

#[utoipa::path(
    get,
    path = "/lan_ipv6/{iface_name}",
    tag = "LAN IPv6",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = CommonApiResp<LanIPv6ServiceConfigV2>),
        (status = 404, description = "Not found")
    )
)]
async fn get_lan_ipv6_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<LanIPv6ServiceConfigV2> {
    if let Some(iface_config) = state.lan_ipv6_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "LAN IPv6" })?
    }
}

#[utoipa::path(
    put,
    path = "/lan_ipv6",
    tag = "LAN IPv6",
    request_body = LanIPv6ServiceConfigV2,
    responses((status = 200, description = "Success"))
)]
async fn handle_lan_ipv6(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<LanIPv6ServiceConfigV2>,
) -> LandscapeApiResult<()> {
    state.validate_zone(&config).await?;
    let prefix_infos = state.ipv6_pd_service.get_ipv6_prefix_infos();
    config.config.validate_with_prefix_infos(Some(&prefix_infos))?;

    // Cross-interface conflict detection
    let other_configs: Vec<LanIPv6ServiceConfigV2> =
        state.lan_ipv6_service.get_repository().list().await.unwrap_or_default();
    validate_cross_interface_v2_with_prefix_infos(&config, &other_configs, Some(&prefix_infos))?;

    state.lan_ipv6_service.handle_service_config(config).await?;
    state.static_nat_mapping_config_service.refresh_runtime_rules().await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/lan_ipv6/{iface_name}",
    tag = "LAN IPv6",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_and_stop_lan_ipv6(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<WatchService>> {
    let result = state.lan_ipv6_service.delete_and_stop_iface_service(iface_name).await;
    state.static_nat_mapping_config_service.refresh_runtime_rules().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/lan_ipv6/{iface_name}/dhcpv6_assigned",
    tag = "LAN IPv6",
    operation_id = "get_lan_ipv6_dhcpv6_assigned_by_iface_name",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = CommonApiResp<Option<DHCPv6OfferInfo>>))
)]
async fn get_dhcpv6_assigned_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DHCPv6OfferInfo>> {
    LandscapeApiResp::success(
        state.lan_ipv6_service.get_dhcpv6_assigned_by_iface_name(iface_name).await,
    )
}

#[utoipa::path(
    get,
    path = "/lan_ipv6/dhcpv6_assigned",
    tag = "LAN IPv6",
    operation_id = "get_all_lan_ipv6_dhcpv6_assigned",
    responses((status = 200, body = CommonApiResp<HashMap<String, DHCPv6OfferInfo>>))
)]
async fn get_all_dhcpv6_assigned(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DHCPv6OfferInfo>> {
    LandscapeApiResp::success(state.lan_ipv6_service.get_dhcpv6_assigned().await)
}
