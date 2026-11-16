use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::sys_config::{GetUiConfigResponse, LandscapeUiConfig, UpdateUiConfigRequest};

use crate::LandscapeApp;
use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

#[utoipa::path(
    get,
    path = "/config/edit/ui",
    tag = "System Config",
    operation_id = "get_ui_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetUiConfigResponse>))
)]
pub async fn get_ui_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetUiConfigResponse> {
    let (ui, hash) = state.system.config_service.get_ui_config_from_file().await?;
    LandscapeApiResp::success(GetUiConfigResponse { ui, hash })
}

#[utoipa::path(
    get,
    path = "/config/ui",
    tag = "System Config",
    operation_id = "get_ui_config_fast",
    responses((status = 200, description = "Success", body = CommonApiResp<LandscapeUiConfig>))
)]
pub async fn get_ui_config_fast(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<LandscapeUiConfig> {
    let ui_config = state.system.config_service.get_ui_config_from_memory();
    LandscapeApiResp::success(ui_config)
}

#[utoipa::path(
    post,
    path = "/config/edit/ui",
    tag = "System Config",
    operation_id = "update_ui_config",
    request_body = UpdateUiConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_ui_config(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<UpdateUiConfigRequest>,
) -> LandscapeApiResult<()> {
    state.system.config_service.update_ui_config(payload.new_ui, payload.expected_hash).await?;
    LandscapeApiResp::success(())
}
