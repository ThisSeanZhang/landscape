use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::{
    config::ConfigId,
    mac_binding::{IpMacBinding, ValidateIpPayload},
};

use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub async fn get_mac_binding_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/mac_bindings", get(list_mac_bindings).post(push_mac_binding))
        .route("/mac_bindings/validate_ip", post(handle_validate_ip))
        .route(
            "/mac_bindings/{id}",
            get(get_mac_binding).put(update_mac_binding).delete(delete_mac_binding),
        )
        .route("/mac_bindings/check_invalid/{iface_name}", get(check_iface_validity))
}

async fn check_iface_validity(
    State(app): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Vec<IpMacBinding>> {
    // 获取该网卡的 DHCP 范围用于校验
    let config = app.dhcp_v4_server_service.get_config_by_name(iface_name.clone()).await;

    if let Some(c) = config {
        let invalid = app
            .mac_binding_service
            .find_out_of_range_bindings(iface_name, c.config.server_ip_addr, c.config.network_mask)
            .await
            .map_err(crate::error::LandscapeApiError::BadRequest)?;

        LandscapeApiResp::success(invalid)
    } else {
        // 如果网卡没开 DHCP，可以认为该网卡下的所有绑定都是“失效”的，或者返回空（由具体逻辑定）
        // 这里根据需求，既然是为了“修改后提醒”，没开 DHCP 说明可能被删除了。
        LandscapeApiResp::success(vec![])
    }
}

async fn handle_validate_ip(
    State(app): State<LandscapeApp>,
    Json(payload): Json<ValidateIpPayload>,
) -> LandscapeApiResult<bool> {
    let result = app
        .mac_binding_service
        .validate_ip_range(payload.iface_name, payload.ipv4)
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(result)
}

async fn list_mac_bindings(
    State(app): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpMacBinding>> {
    let result = app.mac_binding_service.list().await;
    LandscapeApiResp::success(result)
}

async fn get_mac_binding(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<IpMacBinding>> {
    let result = app.mac_binding_service.get(id.into()).await;
    LandscapeApiResp::success(result)
}

async fn push_mac_binding(
    State(app): State<LandscapeApp>,
    Json(payload): Json<IpMacBinding>,
) -> LandscapeApiResult<()> {
    app.mac_binding_service
        .push(payload)
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(())
}

async fn update_mac_binding(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    Json(mut payload): Json<IpMacBinding>,
) -> LandscapeApiResult<()> {
    payload.id = id.into();
    app.mac_binding_service
        .push(payload)
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(())
}

async fn delete_mac_binding(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    app.mac_binding_service
        .delete(id.into())
        .await
        .map_err(crate::error::LandscapeApiError::BadRequest)?;
    LandscapeApiResp::success(())
}
