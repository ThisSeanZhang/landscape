use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{
    GetGatewayConfigResponse, LandscapeGatewayConfig, UpdateGatewayConfigRequest,
};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

#[utoipa::path(
    get,
    path = "/config/edit/gateway",
    tag = "System Config",
    operation_id = "get_gateway_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetGatewayConfigResponse>))
)]
pub async fn get_gateway_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetGatewayConfigResponse> {
    let (gateway, hash) = state.config_service.get_gateway_config_from_file().await;
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
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<LandscapeGatewayConfig> {
    let gateway_config = state.config_service.get_gateway_config_from_memory();
    LandscapeApiResp::success(gateway_config)
}

#[utoipa::path(
    post,
    path = "/config/edit/gateway",
    tag = "System Config",
    operation_id = "update_gateway_config",
    request_body = UpdateGatewayConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_gateway_config(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<UpdateGatewayConfigRequest>,
) -> LandscapeApiResult<()> {
    state.config_service.update_gateway_config(payload.new_gateway, payload.expected_hash).await?;
    LandscapeApiResp::success(())
}
