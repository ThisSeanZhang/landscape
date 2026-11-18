use crate::app::system_config::{SystemConfigChange, SystemConfigEditor};
use axum::extract::State;
use landscape_common::sys_config::ChangePasswordRequest;

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

#[utoipa::path(
    post,
    path = "/config/edit/auth",
    tag = "System Config",
    operation_id = "change_password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully"),
        (status = 400, description = "Validation error")
    )
)]
pub async fn update_auth_config(
    State(editor): State<SystemConfigEditor>,
    JsonBody(req): JsonBody<ChangePasswordRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::Password(req)).await?;
    LandscapeApiResp::success(())
}
