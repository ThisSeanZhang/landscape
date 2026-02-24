use axum::extract::{Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::dns::check::{CheckChainDnsResult, CheckDnsReq};
use landscape_common::service::{DefaultWatchServiceStatus, ServiceStatus};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dns_service_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_dns_service_status, start_dns_service, stop_dns_service))
        .routes(routes!(check_domain))
}

#[utoipa::path(
    get,
    path = "/dns",
    tag = "DNS Service",
    operation_id = "get_dns_service_status",
    responses((status = 200, body = inline(CommonApiResp<ServiceStatus>)))
)]
async fn get_dns_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<DefaultWatchServiceStatus> {
    LandscapeApiResp::success(state.dns_service.get_status().await)
}

#[utoipa::path(
    post,
    path = "/dns",
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
    path = "/dns",
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
    path = "/dns/check",
    tag = "DNS Service",
    operation_id = "check_domain",
    params(CheckDnsReq),
    responses((status = 200, body = inline(CommonApiResp<CheckChainDnsResult>)))
)]
async fn check_domain(
    State(state): State<LandscapeApp>,
    Query(req): Query<CheckDnsReq>,
) -> LandscapeApiResult<CheckChainDnsResult> {
    LandscapeApiResp::success(state.dns_service.check_domain(req).await)
}
