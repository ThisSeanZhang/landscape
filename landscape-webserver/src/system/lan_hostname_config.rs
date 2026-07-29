use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::LandscapeLanHostnameConfig;
use landscape_common::sys_service::lan_hostname::{
    GetLanHostnameConfigResponse, UpdateLanHostnameConfigRequest,
};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

#[utoipa::path(
    get,
    path = "/config/edit/lan_hostname",
    tag = "System Config",
    operation_id = "get_lan_hostname_config",
    responses((status = 200, body = CommonApiResp<GetLanHostnameConfigResponse>))
)]
pub async fn get_lan_hostname_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetLanHostnameConfigResponse> {
    let (lan_hostname, hash) = state.config_service.get_lan_hostname_config_from_file().await;
    LandscapeApiResp::success(GetLanHostnameConfigResponse { lan_hostname, hash })
}

#[utoipa::path(
    get,
    path = "/config/lan_hostname",
    tag = "System Config",
    operation_id = "get_lan_hostname_config_fast",
    responses((status = 200, body = CommonApiResp<LandscapeLanHostnameConfig>))
)]
pub async fn get_lan_hostname_config_fast(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<LandscapeLanHostnameConfig> {
    let config = state.config_service.get_lan_hostname_config_from_memory();
    LandscapeApiResp::success(config)
}

#[utoipa::path(
    post,
    path = "/config/edit/lan_hostname",
    tag = "System Config",
    operation_id = "update_lan_hostname_config",
    request_body = UpdateLanHostnameConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_lan_hostname_config(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<UpdateLanHostnameConfigRequest>,
) -> LandscapeApiResult<()> {
    let new_lan_hostname = payload.new_lan_hostname.normalized()?;
    state
        .config_service
        .update_lan_hostname_config(new_lan_hostname, payload.expected_hash)
        .await?;
    let runtime = state.config_service.get_lan_hostname_runtime_config();
    state.dns_service.update_lan_hostname_config(runtime);
    LandscapeApiResp::success(())
}
