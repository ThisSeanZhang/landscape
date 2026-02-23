use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::controller_service_v2::ControllerService;
use landscape_common::{
    config::ConfigId,
    enrolled_device::{EnrolledDevice, EnrolledDeviceError, ValidateIpPayload},
};

use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub async fn get_enrolled_device_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/enrolled_devices", get(list_enrolled_devices).post(push_enrolled_device))
        .route("/enrolled_devices/validate_ip", post(handle_validate_ip))
        .route(
            "/enrolled_devices/{id}",
            get(get_enrolled_device).put(update_enrolled_device).delete(delete_enrolled_device),
        )
        .route("/enrolled_devices/check_invalid/{iface_name}", get(check_iface_validity))
}

async fn check_iface_validity(
    State(app): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Vec<EnrolledDevice>> {
    // 获取该网卡的 DHCP 范围用于校验
    let config = app.dhcp_v4_server_service.get_config_by_name(iface_name.clone()).await;

    if let Some(c) = config {
        let invalid = app
            .enrolled_device_service
            .find_out_of_range_bindings(iface_name, c.config.server_ip_addr, c.config.network_mask)
            .await
            .map_err(EnrolledDeviceError::InvalidData)?;

        LandscapeApiResp::success(invalid)
    } else {
        // 如果网卡没开 DHCP，可以认为该网卡下的所有绑定都是"失效"的，或者返回空（由具体逻辑定）
        // 这里根据需求，既然是为了"修改后提醒"，没开 DHCP 说明可能被删除了。
        LandscapeApiResp::success(vec![])
    }
}

async fn handle_validate_ip(
    State(app): State<LandscapeApp>,
    Json(payload): Json<ValidateIpPayload>,
) -> LandscapeApiResult<bool> {
    let result = app
        .enrolled_device_service
        .validate_ip_range(payload.iface_name, payload.ipv4)
        .await
        .map_err(EnrolledDeviceError::InvalidData)?;
    LandscapeApiResp::success(result)
}

async fn list_enrolled_devices(
    State(app): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<EnrolledDevice>> {
    let result = app.enrolled_device_service.list().await;
    LandscapeApiResp::success(result)
}

async fn get_enrolled_device(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<EnrolledDevice>> {
    let result = app.enrolled_device_service.get(id.into()).await;
    LandscapeApiResp::success(result)
}

async fn push_enrolled_device(
    State(app): State<LandscapeApp>,
    Json(payload): Json<EnrolledDevice>,
) -> LandscapeApiResult<()> {
    app.enrolled_device_service.push(payload).await.map_err(EnrolledDeviceError::InvalidData)?;
    LandscapeApiResp::success(())
}

async fn update_enrolled_device(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    Json(mut payload): Json<EnrolledDevice>,
) -> LandscapeApiResult<()> {
    payload.id = id.into();
    app.enrolled_device_service.push(payload).await.map_err(EnrolledDeviceError::InvalidData)?;
    LandscapeApiResp::success(())
}

async fn delete_enrolled_device(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    app.enrolled_device_service
        .delete(id.into())
        .await
        .map_err(EnrolledDeviceError::InvalidData)?;
    LandscapeApiResp::success(())
}
