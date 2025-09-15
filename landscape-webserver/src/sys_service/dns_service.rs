use axum::{
    extract::{Query, State},
    routing::get,
    Router,
};
use landscape_common::service::DefaultWatchServiceStatus;
use landscape_dns::{CheckChainDnsResult, CheckDnsReq};

use crate::LandscapeApp;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_dns_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/dns", get(get_dns_service_status).post(start_dns_service).delete(stop_dns_service))
        .route("/dns/check", get(check_domain))
}

async fn get_dns_service_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<DefaultWatchServiceStatus> {
    LandscapeApiResp::success(state.dns_service.get_status().await)
}

async fn start_dns_service(State(state): State<LandscapeApp>) {
    state.dns_service.start_dns_service().await;
}

async fn stop_dns_service(State(state): State<LandscapeApp>) {
    state.dns_service.stop().await;
}

async fn check_domain(
    State(state): State<LandscapeApp>,
    Query(req): Query<CheckDnsReq>,
) -> LandscapeApiResult<CheckChainDnsResult> {
    LandscapeApiResp::success(state.dns_service.check_domain(req).await)
}
