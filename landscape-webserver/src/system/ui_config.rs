use crate::app::system_config::{SystemConfigChange, SystemConfigEditor};
use axum::extract::State;
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::sys_config::{GetUiConfigResponse, LandscapeUiConfig, UpdateUiConfigRequest};

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
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetUiConfigResponse> {
    let (ui, hash) = config.get_ui_config_from_file().await?;
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
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<LandscapeUiConfig> {
    let ui_config = config.get_ui_config_from_memory();
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
    State(editor): State<SystemConfigEditor>,
    JsonBody(payload): JsonBody<UpdateUiConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::Ui(payload)).await?;
    LandscapeApiResp::success(())
}
