use axum::extract::{Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::dns::check::{CheckChainDnsResult, CheckDnsReq};
use landscape_common::service::ServiceStatus;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dns_service_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_dns_service_status, start_dns_service, stop_dns_service))
        .routes(routes!(check_domain, invalidate_domain_cache, refresh_domain_cache))
}

#[utoipa::path(
    get,
    path = "/service",
    tag = "DNS Service",
    operation_id = "get_dns_service_status",
    responses((status = 200, description = "Success", body = CommonApiResp<ServiceStatus>))
)]
async fn get_dns_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<ServiceStatus> {
    LandscapeApiResp::success(state.dns_service.get_status().await)
}

#[utoipa::path(
    post,
    path = "/service",
    tag = "DNS Service",
    operation_id = "start_dns_service",
    responses((status = 200, description = "Success"))
)]
async fn start_dns_service(State(state): State<LandscapeApp>) -> LandscapeApiResult<()> {
    state.dns_service.start_dns_service().await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/service",
    tag = "DNS Service",
    operation_id = "stop_dns_service",
    responses((status = 200, description = "Success"))
)]
async fn stop_dns_service(State(state): State<LandscapeApp>) -> LandscapeApiResult<()> {
    state.dns_service.stop().await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/service/check",
    tag = "DNS Service",
    operation_id = "check_domain",
    summary = "Inspect DNS resolution for a flow",
    description = "Returns DNS rule matching metadata together with query results. Use `apply_filter=false` to inspect the full upstream/cache result while still seeing whether the query would be filtered by rule. Use `apply_filter=true` when you want returned records to match runtime filtering behavior.",
    params(CheckDnsReq),
    responses((
        status = 200,
        description = "DNS inspection result with optional rule-filtered records",
        body = CommonApiResp<CheckChainDnsResult>
    ))
)]
async fn check_domain(
    State(state): State<LandscapeApp>,
    Query(req): Query<CheckDnsReq>,
) -> LandscapeApiResult<CheckChainDnsResult> {
    LandscapeApiResp::success(state.dns_service.check_domain(req).await)
}

#[utoipa::path(
    delete,
    path = "/service/cache",
    tag = "DNS Service",
    operation_id = "invalidate_domain_cache",
    summary = "Delete DNS runtime cache entry",
    description = "Deletes the DNS runtime cache entry for the selected flow, domain, and record type, then returns the latest inspection result.",
    params(CheckDnsReq),
    responses((
        status = 200,
        description = "DNS inspection result after cache deletion",
        body = CommonApiResp<CheckChainDnsResult>
    ))
)]
async fn invalidate_domain_cache(
    State(state): State<LandscapeApp>,
    Query(req): Query<CheckDnsReq>,
) -> LandscapeApiResult<CheckChainDnsResult> {
    LandscapeApiResp::success(state.dns_service.invalidate_domain_cache(req).await?)
}

#[utoipa::path(
    post,
    path = "/service/cache/refresh",
    tag = "DNS Service",
    operation_id = "refresh_domain_cache",
    summary = "Refresh DNS runtime cache entry from upstream",
    description = "Queries upstream for the selected flow, domain, and record type, updates the DNS runtime cache, then returns the refreshed inspection result.",
    params(CheckDnsReq),
    responses((
        status = 200,
        description = "DNS inspection result after cache refresh",
        body = CommonApiResp<CheckChainDnsResult>
    ))
)]
async fn refresh_domain_cache(
    State(state): State<LandscapeApp>,
    Query(req): Query<CheckDnsReq>,
) -> LandscapeApiResult<CheckChainDnsResult> {
    LandscapeApiResp::success(state.dns_service.refresh_domain_cache(req).await?)
}
