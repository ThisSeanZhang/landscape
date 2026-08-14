use axum::extract::{Path, State};
use landscape::{get_existing_linklocal, get_iface_by_name, set_iface_ip_no_limit};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::database::LandscapeStore;
use landscape_common::dev::iface::{IfaceTopology, IfacesInfo};
use landscape_common::service::controller::ControllerService;
use landscape_common::{
    config_service::iface::{IfaceCpuSoftBalance, NetworkIfaceConfig},
    dev::iface::BridgeCreate,
};
use landscape_common::{
    config_service::iface::{IfaceZoneType, WifiMode},
    dev::iface::{AddController, ChangeZone},
};
use std::net::IpAddr;
use tracing::error;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub fn get_iface_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_ifaces_old))
        .routes(routes!(get_ifaces_new))
        .routes(routes!(get_wan_ifaces))
        .routes(routes!(get_wan_candidates))
        .routes(routes!(manage_ifaces))
        .routes(routes!(create_bridge))
        .routes(routes!(delete_bridge))
        .routes(routes!(set_controller))
        .routes(routes!(change_zone))
        .routes(routes!(change_dev_status))
        .routes(routes!(change_dev_boot_status))
        .routes(routes!(change_wifi_mode))
        .routes(routes!(get_cpu_balance, set_cpu_balance))
}

#[utoipa::path(
    get,
    path = "/all_old",
    tag = "Interfaces",
    operation_id = "get_ifaces_old",
    responses((status = 200, body = CommonApiResp<Vec<IfaceTopology>>))
)]
async fn get_ifaces_old(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IfaceTopology>> {
    let result = state.iface_config_service.old_read_ifaces().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/all",
    tag = "Interfaces",
    operation_id = "get_ifaces_new",
    responses((status = 200, body = CommonApiResp<IfacesInfo>))
)]
async fn get_ifaces_new(State(state): State<LandscapeApp>) -> LandscapeApiResult<IfacesInfo> {
    let result = state.iface_config_service.read_ifaces().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/wan_configs",
    tag = "Interfaces",
    operation_id = "get_wan_ifaces",
    responses((status = 200, body = CommonApiResp<Vec<NetworkIfaceConfig>>))
)]
async fn get_wan_ifaces(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<NetworkIfaceConfig>> {
    let result = state.iface_config_service.get_all_wan_iface_config().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/wan_candidates",
    tag = "Interfaces",
    operation_id = "get_wan_candidates",
    responses((status = 200, body = CommonApiResp<Vec<String>>))
)]
async fn get_wan_candidates(State(state): State<LandscapeApp>) -> LandscapeApiResult<Vec<String>> {
    let mut names: Vec<String> = state
        .iface_config_service
        .get_all_wan_iface_config()
        .await
        .into_iter()
        .map(|c| c.name)
        .collect();

    let pppd_configs = state.pppd_service.get_repository().list().await.unwrap_or_default();

    for cfg in pppd_configs {
        if !names.iter().any(|n| n == &cfg.iface_name) {
            names.push(cfg.iface_name);
        }
    }

    LandscapeApiResp::success(names)
}

#[utoipa::path(
    post,
    path = "/manage/{iface_name}",
    tag = "Interfaces",
    operation_id = "manage_iface",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success"))
)]
async fn manage_ifaces(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<()> {
    state.iface_config_service.manage_dev(iface_name).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/bridge",
    tag = "Interfaces",
    operation_id = "create_bridge",
    request_body = BridgeCreate,
    responses((status = 200, description = "Success"))
)]
async fn create_bridge(
    State(state): State<LandscapeApp>,
    JsonBody(bridge_create_request): JsonBody<BridgeCreate>,
) -> LandscapeApiResult<()> {
    state.iface_config_service.create_bridge(bridge_create_request).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/bridge/{bridge_name}",
    tag = "Interfaces",
    operation_id = "delete_bridge",
    params(("bridge_name" = String, Path, description = "Bridge name")),
    responses((status = 200, description = "Success"))
)]
async fn delete_bridge(
    State(state): State<LandscapeApp>,
    Path(bridge_name): Path<String>,
) -> LandscapeApiResult<()> {
    state.remove_all_iface_service(&bridge_name).await;
    state.iface_config_service.delete_bridge(bridge_name).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/controller",
    tag = "Interfaces",
    operation_id = "set_controller",
    request_body = AddController,
    responses((status = 200, description = "Success"))
)]
async fn set_controller(
    State(state): State<LandscapeApp>,
    JsonBody(controller): JsonBody<AddController>,
) -> LandscapeApiResult<()> {
    state.iface_config_service.set_controller(controller).await;
    LandscapeApiResp::success(())
}

// 切换 网卡 所属区域
#[utoipa::path(
    post,
    path = "/zone",
    tag = "Interfaces",
    operation_id = "change_zone",
    request_body = ChangeZone,
    responses((status = 200, description = "Success"))
)]
async fn change_zone(
    State(state): State<LandscapeApp>,
    JsonBody(change_zone): JsonBody<ChangeZone>,
) -> LandscapeApiResult<()> {
    let should_cleanup_dhcp_v4 = matches!(change_zone.zone.clone(), IfaceZoneType::Undefined);
    let dhcp_v4_cleanup = if should_cleanup_dhcp_v4 {
        state.dhcp_v4_server_service.get_config_by_name(change_zone.iface_name.clone()).await
    } else {
        None
    };

    state.remove_all_iface_service(&change_zone.iface_name).await;
    if let Some(config) = dhcp_v4_cleanup.as_ref() {
        state.dhcp_v4_server_service.cleanup_lingering_iface_addr_if_present(config).await;
    }
    state.iface_config_service.change_zone(change_zone.clone()).await;
    if matches!(change_zone.zone, IfaceZoneType::Wan)
        && get_existing_linklocal(&change_zone.iface_name).is_none()
    {
        if let Some(iface) = get_iface_by_name(&change_zone.iface_name).await {
            if let Some(ref mac) = iface.mac {
                let ll = mac.to_ipv6_link_local();
                if !set_iface_ip_no_limit(&change_zone.iface_name, IpAddr::V6(ll), 64).await {
                    error!("Failed to set link-local address {ll} on {}", change_zone.iface_name);
                }
            }
        }
    }
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/{iface_name}/status/{status}",
    tag = "Interfaces",
    operation_id = "change_dev_status",
    params(
        ("iface_name" = String, Path, description = "Interface name"),
        ("status" = bool, Path, description = "Enable in boot")
    ),
    responses((status = 200, description = "Success"))
)]
async fn change_dev_status(
    State(state): State<LandscapeApp>,
    Path((iface_name, enable_in_boot)): Path<(String, bool)>,
) -> LandscapeApiResult<()> {
    state.iface_config_service.change_dev_status(iface_name, enable_in_boot).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/{iface_name}/boot/{status}",
    tag = "Interfaces",
    operation_id = "change_dev_boot_status",
    params(
        ("iface_name" = String, Path, description = "Interface name"),
        ("status" = bool, Path, description = "Enable in boot")
    ),
    responses((status = 200, description = "Success"))
)]
async fn change_dev_boot_status(
    State(state): State<LandscapeApp>,
    Path((iface_name, enable_in_boot)): Path<(String, bool)>,
) -> LandscapeApiResult<()> {
    state.iface_config_service.change_dev_boot_status(iface_name, enable_in_boot).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/{iface_name}/wifi_mode/{mode}",
    tag = "Interfaces",
    operation_id = "change_wifi_mode",
    params(
        ("iface_name" = String, Path, description = "Interface name"),
        ("mode" = WifiMode, Path, description = "WiFi mode")
    ),
    responses((status = 200, description = "Success"))
)]
async fn change_wifi_mode(
    State(state): State<LandscapeApp>,
    Path((iface_name, mode)): Path<(String, WifiMode)>,
) -> LandscapeApiResult<()> {
    state.iface_config_service.change_wifi_mode(iface_name, mode).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/{iface_name}/cpu_balance",
    tag = "Interfaces",
    operation_id = "get_cpu_balance",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = CommonApiResp<Option<IfaceCpuSoftBalance>>))
)]
async fn get_cpu_balance(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<IfaceCpuSoftBalance>> {
    let iface = state.iface_config_service.get_iface_config(iface_name).await;
    LandscapeApiResp::success(iface.and_then(|iface| iface.xps_rps))
}

#[utoipa::path(
    post,
    path = "/{iface_name}/cpu_balance",
    tag = "Interfaces",
    operation_id = "set_cpu_balance",
    params(("iface_name" = String, Path, description = "Interface name")),
    request_body = Option<IfaceCpuSoftBalance>,
    responses((status = 200, description = "Success"))
)]
async fn set_cpu_balance(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
    JsonBody(balance): JsonBody<Option<IfaceCpuSoftBalance>>,
) -> LandscapeApiResult<()> {
    state.iface_config_service.change_cpu_balance(iface_name, balance).await;
    LandscapeApiResp::success(())
}
