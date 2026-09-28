use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{
    GetTimeConfigResponse, LandscapeTimeConfig, UpdateTimeConfigRequest,
};
use landscape_common::sys_service::time_sync::TimeSyncStatus;

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

#[utoipa::path(
    get,
    path = "/time/sync_status",
    tag = "System Config",
    operation_id = "get_time_sync_status",
    responses((status = 200, description = "Success", body = CommonApiResp<TimeSyncStatus>))
)]
pub async fn get_time_sync_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<TimeSyncStatus> {
    LandscapeApiResp::success(state.time_service.status())
}

#[utoipa::path(
    get,
    path = "/config/edit/time",
    tag = "System Config",
    operation_id = "get_time_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetTimeConfigResponse>))
)]
pub async fn get_time_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetTimeConfigResponse> {
    let (time, hash) = state.config_service.get_time_config_from_file().await;
    LandscapeApiResp::success(GetTimeConfigResponse { time, hash })
}

#[utoipa::path(
    get,
    path = "/config/time",
    tag = "System Config",
    operation_id = "get_time_config_fast",
    responses((status = 200, description = "Success", body = CommonApiResp<LandscapeTimeConfig>))
)]
pub async fn get_time_config_fast(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<LandscapeTimeConfig> {
    let time_config = state.config_service.get_time_config_from_memory();
    LandscapeApiResp::success(time_config)
}

#[utoipa::path(
    post,
    path = "/config/edit/time",
    tag = "System Config",
    operation_id = "update_time_config",
    request_body = UpdateTimeConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_time_config(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<UpdateTimeConfigRequest>,
) -> LandscapeApiResult<()> {
    state.config_service.update_time_config(payload.new_time, payload.expected_hash).await?;

    let time_runtime = state.config_service.get_time_runtime_config();
    state.time_service.update_config(time_runtime);

    LandscapeApiResp::success(())
}
