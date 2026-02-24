use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::dhcp::v4_server::config::DHCPv4ServiceConfig;
use landscape_common::dhcp::v4_server::status::{ArpScanInfo, DHCPv4OfferInfo};
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::dhcp::DhcpError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dhcp_v4_service_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_iface_service_status))
        .routes(routes!(handle_service_config))
        .routes(routes!(get_all_iface_assigned_ips))
        .routes(routes!(get_all_iface_arp_scan_info))
        .routes(routes!(get_iface_service_config, delete_and_stop_iface_service))
        .routes(routes!(get_assigned_ips_by_iface_name))
        .routes(routes!(get_arp_scan_info_by_iface_name))
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/assigned_ips",
    tag = "DHCPv4",
    operation_id = "get_all_dhcp_v4_assigned_ips",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, DHCPv4OfferInfo>>)))
)]
async fn get_all_iface_assigned_ips(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DHCPv4OfferInfo>> {
    LandscapeApiResp::success(state.dhcp_v4_server_service.get_assigned_ips().await)
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/{iface_name}/assigned_ips",
    tag = "DHCPv4",
    operation_id = "get_dhcp_v4_assigned_ips_by_iface_name",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<DHCPv4OfferInfo>>)))
)]
async fn get_assigned_ips_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DHCPv4OfferInfo>> {
    LandscapeApiResp::success(
        state.dhcp_v4_server_service.get_assigned_ips_by_iface_name(iface_name).await,
    )
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/arp_scan_info",
    tag = "DHCPv4",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, Vec<ArpScanInfo>>>)))
)]
async fn get_all_iface_arp_scan_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, Vec<ArpScanInfo>>> {
    LandscapeApiResp::success(state.dhcp_v4_server_service.get_arp_scan_info().await)
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/{iface_name}/arp_scan_info",
    tag = "DHCPv4",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<Vec<ArpScanInfo>>>)))
)]
async fn get_arp_scan_info_by_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<Vec<ArpScanInfo>>> {
    LandscapeApiResp::success(
        state.dhcp_v4_server_service.get_arp_scan_ips_by_iface_name(iface_name).await,
    )
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/status",
    tag = "DHCPv4",
    operation_id = "get_all_dhcp_v4_service_status",
    responses((status = 200, body = inline(CommonApiResp<HashMap<String, ServiceStatus>>)))
)]
async fn get_all_iface_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(state.dhcp_v4_server_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/dhcp_v4/{iface_name}",
    tag = "DHCPv4",
    operation_id = "get_dhcp_v4_service_config",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = inline(CommonApiResp<DHCPv4ServiceConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_service_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<DHCPv4ServiceConfig> {
    if let Some(iface_config) = state.dhcp_v4_server_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(DhcpError::ConfigNotFound("DHCPv4".into()))?
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
    if let Err(conflict_msg) = state.dhcp_v4_server_service.check_ip_range_conflict(&config).await {
        return Err(DhcpError::IpConflict(conflict_msg))?;
    }

    state.dhcp_v4_server_service.handle_service_config(config).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/dhcp_v4/{iface_name}",
    tag = "DHCPv4",
    operation_id = "delete_and_stop_dhcp_v4_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<ServiceStatus>>)))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<DefaultWatchServiceStatus>> {
    LandscapeApiResp::success(
        state.dhcp_v4_server_service.delete_and_stop_iface_service(iface_name).await,
    )
}
