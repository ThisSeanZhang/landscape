use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::controller_service_v2::ConfigController;
use landscape_common::{config::ConfigId, dns::upstream::DnsUpstreamConfig};

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};
use crate::{error::LandscapeApiError, LandscapeApp};

pub async fn get_dns_upstream_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/dns_upstreams", get(get_dns_upstreams).post(add_dns_upstream))
        .route("/dns_upstreams/set_many", post(add_many_dns_upstreams))
        .route("/dns_upstreams/{id}", get(get_dns_upstream).delete(del_dns_upstream))
}

async fn get_dns_upstreams(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DnsUpstreamConfig>> {
    let result = state.dns_upstream_service.list().await;
    LandscapeApiResp::success(result)
}

async fn get_dns_upstream(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DnsUpstreamConfig> {
    let result = state.dns_upstream_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(LandscapeApiError::NotFound(format!("Dns Upstream Config id: {:?}", id)))
    }
}

async fn add_many_dns_upstreams(
    State(state): State<LandscapeApp>,
    Json(dns_upstreams): Json<Vec<DnsUpstreamConfig>>,
) -> LandscapeApiResult<()> {
    state.dns_upstream_service.set_list(dns_upstreams).await;
    LandscapeApiResp::success(())
}

async fn add_dns_upstream(
    State(state): State<LandscapeApp>,
    Json(dns_upstream): Json<DnsUpstreamConfig>,
) -> LandscapeApiResult<DnsUpstreamConfig> {
    let result = state.dns_upstream_service.set(dns_upstream).await;
    LandscapeApiResp::success(result)
}

async fn del_dns_upstream(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.dns_upstream_service.delete(id).await;
    LandscapeApiResp::success(())
}
