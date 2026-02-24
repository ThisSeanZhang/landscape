use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::iface::{IfaceTopology, IfacesInfo};
use landscape_common::{
    config::iface::WifiMode,
    iface::{AddController, ChangeZone},
};
use landscape_common::{
    config::iface::{IfaceCpuSoftBalance, NetworkIfaceConfig},
    iface::BridgeCreate,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub fn get_iface_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_ifaces))
        .routes(routes!(get_new_ifaces))
        .routes(routes!(get_wan_ifaces))
        .routes(routes!(manage_ifaces))
        .routes(routes!(create_bridge))
        .routes(routes!(delete_bridge))
        .routes(routes!(set_controller))
        .routes(routes!(change_zone))
        .routes(routes!(change_dev_status))
        .routes(routes!(change_wifi_mode))
        .routes(routes!(get_cpu_balance, set_cpu_balance))
}

#[utoipa::path(
    get,
    path = "/iface",
    tag = "Iface",
    operation_id = "get_ifaces",
    responses((status = 200, body = inline(CommonApiResp<Vec<IfaceTopology>>)))
)]
async fn get_ifaces(State(state): State<LandscapeApp>) -> LandscapeApiResult<Vec<IfaceTopology>> {
    let result = state.iface_config_service.old_read_ifaces().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/iface/new",
    tag = "Iface",
    operation_id = "get_new_ifaces",
    responses((status = 200, body = inline(CommonApiResp<IfacesInfo>)))
)]
async fn get_new_ifaces(State(state): State<LandscapeApp>) -> LandscapeApiResult<IfacesInfo> {
    let result = state.iface_config_service.read_ifaces().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/iface/wan_configs",
    tag = "Iface",
    operation_id = "get_wan_ifaces",
    responses((status = 200, body = inline(CommonApiResp<Vec<NetworkIfaceConfig>>)))
)]
async fn get_wan_ifaces(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<NetworkIfaceConfig>> {
    let result = state.iface_config_service.get_all_wan_iface_config().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/iface/manage/{iface_name}",
    tag = "Iface",
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
    path = "/iface/bridge",
    tag = "Iface",
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
    path = "/iface/bridge/{bridge_name}",
    tag = "Iface",
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
    path = "/iface/controller",
    tag = "Iface",
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
    path = "/iface/zone",
    tag = "Iface",
    operation_id = "change_zone",
    request_body = ChangeZone,
    responses((status = 200, description = "Success"))
)]
async fn change_zone(
    State(state): State<LandscapeApp>,
    JsonBody(change_zone): JsonBody<ChangeZone>,
) -> LandscapeApiResult<()> {
    state.remove_all_iface_service(&change_zone.iface_name).await;
    state.iface_config_service.change_zone(change_zone).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/iface/{iface_name}/status/{status}",
    tag = "Iface",
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
    path = "/iface/{iface_name}/wifi_mode/{mode}",
    tag = "Iface",
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
    path = "/iface/{iface_name}/cpu_balance",
    tag = "Iface",
    operation_id = "get_cpu_balance",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Option<IfaceCpuSoftBalance>>)))
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
    path = "/iface/{iface_name}/cpu_balance",
    tag = "Iface",
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
