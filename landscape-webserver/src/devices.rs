use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::enrolled_device::{EnrolledDevice, EnrolledDeviceError, ValidateIpPayload};
use landscape_common::service::controller_service_v2::ControllerService;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub fn get_enrolled_device_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_enrolled_devices, push_enrolled_device))
        .routes(routes!(handle_validate_ip))
        .routes(routes!(get_enrolled_device, update_enrolled_device, delete_enrolled_device))
        .routes(routes!(check_iface_validity))
}

#[utoipa::path(
    get,
    path = "/check_invalid/{iface_name}",
    tag = "Enrolled Devices",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = inline(CommonApiResp<Vec<EnrolledDevice>>)))
)]
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

#[utoipa::path(
    post,
    path = "/validate_ip",
    tag = "Enrolled Devices",
    request_body = ValidateIpPayload,
    responses((status = 200, body = inline(CommonApiResp<bool>)))
)]
async fn handle_validate_ip(
    State(app): State<LandscapeApp>,
    JsonBody(payload): JsonBody<ValidateIpPayload>,
) -> LandscapeApiResult<bool> {
    let result = app
        .enrolled_device_service
        .validate_ip_range(payload.iface_name, payload.ipv4)
        .await
        .map_err(EnrolledDeviceError::InvalidData)?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/all",
    tag = "Enrolled Devices",
    responses((status = 200, body = inline(CommonApiResp<Vec<EnrolledDevice>>)))
)]
async fn list_enrolled_devices(
    State(app): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<EnrolledDevice>> {
    let result = app.enrolled_device_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/{id}",
    tag = "Enrolled Devices",
    params(("id" = Uuid, Path, description = "Enrolled device ID")),
    responses((status = 200, body = inline(CommonApiResp<Option<EnrolledDevice>>)))
)]
async fn get_enrolled_device(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<EnrolledDevice>> {
    let result = app.enrolled_device_service.get(id.into()).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/all",
    tag = "Enrolled Devices",
    request_body = EnrolledDevice,
    responses((status = 200, description = "Success"))
)]
async fn push_enrolled_device(
    State(app): State<LandscapeApp>,
    JsonBody(payload): JsonBody<EnrolledDevice>,
) -> LandscapeApiResult<()> {
    app.enrolled_device_service.push(payload).await.map_err(EnrolledDeviceError::InvalidData)?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    put,
    path = "/{id}",
    tag = "Enrolled Devices",
    params(("id" = Uuid, Path, description = "Enrolled device ID")),
    request_body = EnrolledDevice,
    responses((status = 200, description = "Success"))
)]
async fn update_enrolled_device(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(mut payload): JsonBody<EnrolledDevice>,
) -> LandscapeApiResult<()> {
    payload.id = id.into();
    app.enrolled_device_service.push(payload).await.map_err(EnrolledDeviceError::InvalidData)?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/{id}",
    tag = "Enrolled Devices",
    params(("id" = Uuid, Path, description = "Enrolled device ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
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
