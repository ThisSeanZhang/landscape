use crate::app::system_config::{SystemConfigChange, SystemConfigEditor};
use axum::extract::State;
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::sys_config::LandscapeLanHostnameConfig;
use landscape_common::sys_config::{GetLanHostnameConfigResponse, UpdateLanHostnameConfigRequest};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

#[utoipa::path(
    get,
    path = "/config/edit/lan_hostname",
    tag = "System Config",
    operation_id = "get_lan_hostname_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetLanHostnameConfigResponse>))
)]
pub async fn get_lan_hostname_config(
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetLanHostnameConfigResponse> {
    let (lan_hostname, hash) = config.get_lan_hostname_config_from_file()?;
    LandscapeApiResp::success(GetLanHostnameConfigResponse { lan_hostname, hash })
}

#[utoipa::path(
    get,
    path = "/config/lan_hostname",
    tag = "System Config",
    operation_id = "get_lan_hostname_config_fast",
    responses((status = 200, description = "Success", body = CommonApiResp<LandscapeLanHostnameConfig>))
)]
pub async fn get_lan_hostname_config_fast(
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<LandscapeLanHostnameConfig> {
    let config = config.get_lan_hostname_config_from_memory();
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
    State(editor): State<SystemConfigEditor>,
    JsonBody(payload): JsonBody<UpdateLanHostnameConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::LanHostname(payload)).await?;
    LandscapeApiResp::success(())
}
