use crate::app::system_config::{SystemConfigChange, SystemConfigEditor};
use axum::extract::State;
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::sys_config::{
    GetDnsCacheConfigResponse, GetDohConfigResponse, UpdateDnsCacheConfigRequest,
    UpdateDohConfigRequest,
};

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
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetDnsCacheConfigResponse> {
    let (cache, hash) = config.get_dns_cache_from_file()?;
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
    State(editor): State<SystemConfigEditor>,
    JsonBody(request): JsonBody<UpdateDnsCacheConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::DnsCache(request)).await?;
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
    State(config): State<LandscapeConfigService>,
) -> LandscapeApiResult<GetDohConfigResponse> {
    let (doh, hash) = config.get_doh_from_file()?;
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
    State(editor): State<SystemConfigEditor>,
    JsonBody(request): JsonBody<UpdateDohConfigRequest>,
) -> LandscapeApiResult<()> {
    editor.apply(SystemConfigChange::Doh(request)).await?;
    LandscapeApiResp::success(())
}
