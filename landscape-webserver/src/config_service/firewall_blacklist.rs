use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use landscape_common::service::controller_service_v2::ConfigController;
use landscape_common::{config::ConfigId, firewall::blacklist::FirewallBlacklistConfig};

use landscape_common::firewall::blacklist::FirewallBlacklistError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_firewall_blacklist_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/firewall_blacklists", get(get_firewall_blacklists).post(add_firewall_blacklist))
        .route(
            "/firewall_blacklists/{id}",
            get(get_firewall_blacklist).delete(del_firewall_blacklist),
        )
}

async fn get_firewall_blacklists(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<FirewallBlacklistConfig>> {
    let result = state.firewall_blacklist_service.list().await;
    LandscapeApiResp::success(result)
}

async fn get_firewall_blacklist(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<FirewallBlacklistConfig> {
    let result = state.firewall_blacklist_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(FirewallBlacklistError::NotFound(id))?
    }
}

async fn add_firewall_blacklist(
    State(state): State<LandscapeApp>,
    Json(config): Json<FirewallBlacklistConfig>,
) -> LandscapeApiResult<FirewallBlacklistConfig> {
    let result = state.firewall_blacklist_service.set(config).await;
    LandscapeApiResp::success(result)
}

async fn del_firewall_blacklist(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.firewall_blacklist_service.delete(id).await;
    LandscapeApiResp::success(())
}
