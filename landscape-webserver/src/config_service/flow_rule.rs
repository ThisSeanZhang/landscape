use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use landscape_common::service::controller_service_v2::FlowConfigController;
use landscape_common::{config::ConfigId, flow::config::FlowConfig};
use landscape_common::{config::FlowId, service::controller_service_v2::ConfigController};

use landscape_common::flow::FlowRuleError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_flow_rule_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/flow_rules", get(get_flow_rules).post(add_flow_rule))
        .route("/flow_rules/{id}", get(get_flow_rule).delete(del_flow_rule))
        .route("/flow_rules/flow_id/{id}", get(get_flow_rule_by_flow_id))
}

async fn get_flow_rules(State(state): State<LandscapeApp>) -> LandscapeApiResult<Vec<FlowConfig>> {
    let mut result = state.flow_rule_service.list().await;
    result.sort_by(|a, b| a.flow_id.cmp(&b.flow_id));
    LandscapeApiResp::success(result)
}

async fn get_flow_rule_by_flow_id(
    State(state): State<LandscapeApp>,
    Path(id): Path<FlowId>,
) -> LandscapeApiResult<FlowConfig> {
    let result = state.flow_rule_service.list_flow_configs(id).await;
    if result.len() > 0 {
        LandscapeApiResp::success(result.first().cloned().unwrap())
    } else {
        Err(FlowRuleError::NotFound(Default::default()))?
    }
}

async fn get_flow_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<FlowConfig> {
    let result = state.flow_rule_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(FlowRuleError::NotFound(id))?
    }
}

async fn add_flow_rule(
    State(state): State<LandscapeApp>,
    Json(flow_rule): Json<FlowConfig>,
) -> LandscapeApiResult<FlowConfig> {
    // Check for duplicate entry rules within the submitted config itself
    {
        let mut seen = std::collections::HashSet::new();
        for rule in &flow_rule.flow_match_rules {
            if !seen.insert(&rule.mode) {
                Err(FlowRuleError::DuplicateEntryRule(rule.mode.to_string()))?;
            }
        }
    }

    // Check for overlap with other flows' entry rules via DB query
    for rule in &flow_rule.flow_match_rules {
        if let Some(conflict) =
            state.flow_rule_service.find_conflict_by_entry_mode(flow_rule.id, &rule.mode).await?
        {
            Err(FlowRuleError::ConflictEntryRule {
                rule: rule.mode.to_string(),
                flow_remark: conflict.remark,
                flow_id: conflict.flow_id,
            })?;
        }
    }

    let result = state.flow_rule_service.set(flow_rule).await;
    LandscapeApiResp::success(result)
}

async fn del_flow_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.flow_rule_service.delete(id).await;
    LandscapeApiResp::success(())
}
