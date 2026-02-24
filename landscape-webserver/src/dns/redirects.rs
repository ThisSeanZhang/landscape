use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::dns::redirect::DNSRedirectRule;
use landscape_common::service::controller_service_v2::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::dns::redirect::DnsRedirectError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dns_redirect_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_dns_redirects, add_dns_redirects))
        .routes(routes!(add_many_dns_redirects))
        .routes(routes!(get_dns_redirect, del_dns_redirects))
}

#[utoipa::path(
    get,
    path = "/redirects",
    tag = "DNS Redirects",
    responses((status = 200, body = inline(CommonApiResp<Vec<DNSRedirectRule>>)))
)]
async fn get_dns_redirects(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DNSRedirectRule>> {
    let result = state.dns_redirect_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/redirects/{id}",
    tag = "DNS Redirects",
    params(("id" = Uuid, Path, description = "DNS redirect rule ID")),
    responses(
        (status = 200, body = inline(CommonApiResp<DNSRedirectRule>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_dns_redirect(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DNSRedirectRule> {
    let result = state.dns_redirect_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(DnsRedirectError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/redirects/batch",
    tag = "DNS Redirects",
    request_body = Vec<DNSRedirectRule>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_dns_redirects(
    State(state): State<LandscapeApp>,
    JsonBody(dns_redirects): JsonBody<Vec<DNSRedirectRule>>,
) -> LandscapeApiResult<()> {
    state.dns_redirect_service.set_list(dns_redirects).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/redirects",
    tag = "DNS Redirects",
    request_body = DNSRedirectRule,
    responses((status = 200, body = inline(CommonApiResp<DNSRedirectRule>)))
)]
async fn add_dns_redirects(
    State(state): State<LandscapeApp>,
    JsonBody(dns_redirect): JsonBody<DNSRedirectRule>,
) -> LandscapeApiResult<DNSRedirectRule> {
    let result = state.dns_redirect_service.set(dns_redirect).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    delete,
    path = "/redirects/{id}",
    tag = "DNS Redirects",
    params(("id" = Uuid, Path, description = "DNS redirect rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_dns_redirects(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.dns_redirect_service.delete(id).await;
    LandscapeApiResp::success(())
}
