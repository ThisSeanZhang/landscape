use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use landscape_common::service::controller_service_v2::ConfigController;
use landscape_common::{config::ConfigId, firewall::FirewallRuleConfig};

use landscape_common::firewall::FirewallRuleError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_firewall_rule_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/firewall_rules", get(get_firewall_rules).post(add_firewall_rule))
        .route("/firewall_rules/{id}", get(get_firewall_rule).delete(del_firewall_rule))
}

async fn get_firewall_rules(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<FirewallRuleConfig>> {
    let mut result = state.fire_wall_rule_service.list().await;
    result.sort_by(|a, b| a.index.cmp(&b.index));
    LandscapeApiResp::success(result)
}

async fn get_firewall_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<FirewallRuleConfig> {
    let result = state.fire_wall_rule_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(FirewallRuleError::NotFound(id))?
    }
}

async fn add_firewall_rule(
    State(state): State<LandscapeApp>,
    Json(firewall_rule): Json<FirewallRuleConfig>,
) -> LandscapeApiResult<FirewallRuleConfig> {
    let result = state.fire_wall_rule_service.set(firewall_rule).await;
    LandscapeApiResp::success(result)
}

async fn del_firewall_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.fire_wall_rule_service.delete(id).await;
    LandscapeApiResp::success(())
}
