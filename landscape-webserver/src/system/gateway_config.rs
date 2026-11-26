use crate::app::system_config::{SystemConfigChange, SystemConfigEditor};
use axum::extract::State;
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::sys_config::{
    GetGatewayConfigResponse, LandscapeGatewayConfig, UpdateGatewayConfigRequest,
};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

#[utoipa::path(
    get,
    path = "/config/edit/gateway",
    tag = "System Config",
    operation_id = "get_gateway_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetGatewayConfigResponse>))
)]
pub async fn get_gateway_config(
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetGatewayConfigResponse> {
    let (gateway, hash) = config.get_gateway_config_from_file()?;
    LandscapeApiResp::success(GetGatewayConfigResponse { gateway, hash })
}

#[utoipa::path(
    get,
    path = "/config/gateway",
    tag = "System Config",
    operation_id = "get_gateway_config_fast",
    responses((status = 200, description = "Success", body = CommonApiResp<LandscapeGatewayConfig>))
)]
pub async fn get_gateway_config_fast(
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<LandscapeGatewayConfig> {
    let gateway_config = config.get_gateway_config_from_memory();
    LandscapeApiResp::success(gateway_config)
}

#[utoipa::path(
    post,
    path = "/config/edit/gateway",
    tag = "System Config",
    operation_id = "update_gateway_config",
    request_body = UpdateGatewayConfigRequest,
    responses(
        (status = 200, description = "Runtime configuration committed"),
        (status = 400, description = "Invalid gateway listener ports"),
        (status = 409, description = "Configuration changed since it was read")
    )
)]
pub async fn update_gateway_config(
    State(editor): State<SystemConfigEditor>,
    JsonBody(payload): JsonBody<UpdateGatewayConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::Gateway(payload)).await?;
    LandscapeApiResp::success(())
}
