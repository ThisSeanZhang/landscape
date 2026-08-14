use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::dns::provider_profile::{
    DnsProviderCredentialCheckRequest, DnsProviderCredentialCheckResult, DnsProviderProfile,
};
use landscape_common::service::controller::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, LandscapeApp};

pub fn get_dns_provider_profile_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_provider_profiles, create_provider_profile))
        .routes(routes!(validate_provider_profile))
        .routes(routes!(get_provider_profile, update_provider_profile, delete_provider_profile))
}

#[utoipa::path(
    get,
    path = "/provider_profiles",
    tag = "DNS Provider Profiles",
    responses((status = 200, body = CommonApiResp<Vec<DnsProviderProfile>>))
)]
async fn list_provider_profiles(
    State(app): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DnsProviderProfile>> {
    LandscapeApiResp::success(app.dns_provider_profile_service.list().await)
}

#[utoipa::path(
    get,
    path = "/provider_profiles/{id}",
    tag = "DNS Provider Profiles",
    params(("id" = Uuid, Path, description = "DNS provider profile ID")),
    responses((status = 200, body = CommonApiResp<Option<DnsProviderProfile>>))
)]
async fn get_provider_profile(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<DnsProviderProfile>> {
    LandscapeApiResp::success(app.dns_provider_profile_service.find_by_id(id).await)
}

#[utoipa::path(
    post,
    path = "/provider_profiles",
    tag = "DNS Provider Profiles",
    request_body = DnsProviderProfile,
    responses((status = 200, body = CommonApiResp<DnsProviderProfile>))
)]
async fn create_provider_profile(
    State(app): State<LandscapeApp>,
    JsonBody(payload): JsonBody<DnsProviderProfile>,
) -> LandscapeApiResult<DnsProviderProfile> {
    LandscapeApiResp::success(app.dns_provider_profile_service.checked_set_profile(payload).await?)
}

#[utoipa::path(
    post,
    path = "/provider_profiles/validate",
    tag = "DNS Provider Profiles",
    request_body = DnsProviderCredentialCheckRequest,
    responses((status = 200, body = CommonApiResp<DnsProviderCredentialCheckResult>))
)]
async fn validate_provider_profile(
    State(app): State<LandscapeApp>,
    JsonBody(payload): JsonBody<DnsProviderCredentialCheckRequest>,
) -> LandscapeApiResult<DnsProviderCredentialCheckResult> {
    LandscapeApiResp::success(app.dns_provider_profile_service.validate_credentials(payload).await?)
}

#[utoipa::path(
    put,
    path = "/provider_profiles/{id}",
    tag = "DNS Provider Profiles",
    params(("id" = Uuid, Path, description = "DNS provider profile ID")),
    request_body = DnsProviderProfile,
    responses((status = 200, body = CommonApiResp<DnsProviderProfile>))
)]
async fn update_provider_profile(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(mut payload): JsonBody<DnsProviderProfile>,
) -> LandscapeApiResult<DnsProviderProfile> {
    payload.id = id;
    LandscapeApiResp::success(app.dns_provider_profile_service.checked_set_profile(payload).await?)
}

#[utoipa::path(
    delete,
    path = "/provider_profiles/{id}",
    tag = "DNS Provider Profiles",
    params(("id" = Uuid, Path, description = "DNS provider profile ID")),
    responses((status = 200, description = "Success"))
)]
async fn delete_provider_profile(
    State(app): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    app.dns_provider_profile_service.delete_profile(id).await?;
    LandscapeApiResp::success(())
}
