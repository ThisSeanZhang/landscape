use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{GetUIConfigResponse, LandscapeUIConfig, UpdateUIConfigRequest};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

#[utoipa::path(
    get,
    path = "/config/edit/ui",
    tag = "System Config",
    operation_id = "get_ui_config",
    responses((status = 200, body = CommonApiResp<GetUIConfigResponse>))
)]
pub async fn get_ui_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetUIConfigResponse> {
    let (config, hash) = state.config_service.get_config_with_hash().await?;
    LandscapeApiResp::success(GetUIConfigResponse { ui: config.ui, hash })
}

#[utoipa::path(
    get,
    path = "/config/ui",
    tag = "System Config",
    operation_id = "get_ui_config_fast",
    responses((status = 200, body = CommonApiResp<LandscapeUIConfig>))
)]
pub async fn get_ui_config_fast(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<LandscapeUIConfig> {
    let ui_config = state.config_service.get_ui_config_from_memory();
    LandscapeApiResp::success(ui_config)
}

#[utoipa::path(
    post,
    path = "/config/edit/ui",
    tag = "System Config",
    operation_id = "update_ui_config",
    request_body = UpdateUIConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_ui_config(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<UpdateUIConfigRequest>,
) -> LandscapeApiResult<()> {
    state.config_service.update_ui_config(payload.new_ui, payload.expected_hash).await?;
    LandscapeApiResp::success(())
}
