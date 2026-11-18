use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::sys_config::{
    GetDnsCacheConfigResponse, GetDohConfigResponse, UpdateDnsCacheConfigRequest,
    UpdateDohConfigRequest,
};

use crate::LandscapeApp;
use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

#[utoipa::path(
    get,
    path = "/config/edit/dns/cache",
    tag = "System Config",
    operation_id = "get_dns_cache_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetDnsCacheConfigResponse>))
)]
pub async fn get_dns_cache_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetDnsCacheConfigResponse> {
    let (cache, hash) = state.system.config_service.get_dns_cache_from_file()?;
    LandscapeApiResp::success(GetDnsCacheConfigResponse { cache, hash })
}

#[utoipa::path(
    post,
    path = "/config/edit/dns/cache",
    tag = "System Config",
    operation_id = "update_dns_cache_config",
    request_body = UpdateDnsCacheConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_dns_cache_config(
    State(state): State<LandscapeApp>,
    JsonBody(request): JsonBody<UpdateDnsCacheConfigRequest>,
) -> LandscapeApiResult<()> {
    state.system.update_dns_cache_config(request).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/config/edit/dns/doh",
    tag = "System Config",
    operation_id = "get_doh_config",
    responses((status = 200, description = "Success", body = CommonApiResp<GetDohConfigResponse>))
)]
pub async fn get_doh_config(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GetDohConfigResponse> {
    let (doh, hash) = state.system.config_service.get_doh_from_file()?;
    LandscapeApiResp::success(GetDohConfigResponse { doh, hash })
}

#[utoipa::path(
    post,
    path = "/config/edit/dns/doh",
    tag = "System Config",
    operation_id = "update_doh_config",
    request_body = UpdateDohConfigRequest,
    responses((status = 200, description = "Success"))
)]
pub async fn update_doh_config(
    State(state): State<LandscapeApp>,
    JsonBody(request): JsonBody<UpdateDohConfigRequest>,
) -> LandscapeApiResult<()> {
    state.system.update_doh_config(request).await?;
    LandscapeApiResp::success(())
}
