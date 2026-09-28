use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{GetDnsConfigResponse, UpdateDnsConfigRequest};

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;
use crate::LandscapeApp;

#[utoipa::path(
    get,
    path = "/config/dns",
    tag = "System Config",
    operation_id = "get_dns_config_fast",
    responses((status = 200, description = "Success", body = CommonApiResp<GetDnsConfigResponse>))
)]
pub async fn get_dns_config_fast(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetDnsConfigResponse> {
    let (dns, hash) = state.config_service.get_dns_config();
    LandscapeApiResp::success(GetDnsConfigResponse { dns, hash })
}

#[utoipa::path(
    get,
    path = "/config/edit/dns",
    tag = "System Config",
    operation_id = "get_dns_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetDnsConfigResponse>))
)]
pub async fn get_dns_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetDnsConfigResponse> {
    let (dns, hash) = state.config_service.get_dns_config_from_file().await;
    LandscapeApiResp::success(GetDnsConfigResponse { dns, hash })
}

#[utoipa::path(
    post,
    path = "/config/edit/dns",
    tag = "System Config",
    operation_id = "update_dns_config",
    request_body = serde_json::Value,
    responses((status = 200, description = "Success", body = CommonApiResp<String>))
)]
pub async fn update_dns_config(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<serde_json::Value>,
) -> LandscapeApiResult<String> {
    let request: UpdateDnsConfigRequest = serde_json::from_value(payload)?;
    state.config_service.update_dns_config(request.new_dns, request.expected_hash).await?;
    let dns_runtime = state.config_service.get_dns_runtime_config();
    state.dns_service.apply_runtime_config(dns_runtime).await;
    LandscapeApiResp::success("success".to_string())
}
