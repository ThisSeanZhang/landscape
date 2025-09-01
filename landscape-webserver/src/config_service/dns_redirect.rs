use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::service::controller_service_v2::ConfigController;
use landscape_common::{config::ConfigId, dns::redirect::DNSRedirectRule};

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};
use crate::{error::LandscapeApiError, LandscapeApp};

pub async fn get_dns_redirect_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/dns_redirects", get(get_dns_redirects).post(add_dns_redirects))
        .route("/dns_redirects/set_many", post(add_many_dns_redirects))
        .route("/dns_redirects/{id}", get(get_dns_redirect).delete(del_dns_redirects))
}

async fn get_dns_redirects(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DNSRedirectRule>> {
    let result = state.dns_redirect_service.list().await;
    LandscapeApiResp::success(result)
}

async fn get_dns_redirect(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DNSRedirectRule> {
    let result = state.dns_redirect_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(LandscapeApiError::NotFound(format!("Dns Redirect Rule id: {:?}", id)))
    }
}

async fn add_many_dns_redirects(
    State(state): State<LandscapeApp>,
    Json(dns_redirects): Json<Vec<DNSRedirectRule>>,
) -> LandscapeApiResult<()> {
    state.dns_redirect_service.set_list(dns_redirects).await;
    LandscapeApiResp::success(())
}

async fn add_dns_redirects(
    State(state): State<LandscapeApp>,
    Json(dns_redirect): Json<DNSRedirectRule>,
) -> LandscapeApiResult<DNSRedirectRule> {
    let result = state.dns_redirect_service.set(dns_redirect).await;
    LandscapeApiResp::success(result)
}

async fn del_dns_redirects(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.dns_redirect_service.delete(id).await;
    LandscapeApiResp::success(())
}
