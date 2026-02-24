use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::service::controller_service_v2::FlowConfigController;
use landscape_common::{config::ConfigId, flow::config::FlowConfig};
use landscape_common::{config::FlowId, service::controller_service_v2::ConfigController};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::flow::FlowRuleError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_flow_rule_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_flow_rules, add_flow_rule))
        .routes(routes!(get_flow_rule, del_flow_rule))
        .routes(routes!(get_flow_rule_by_flow_id))
}

#[utoipa::path(
    get,
    path = "/rules",
    tag = "Flow Rules",
    responses((status = 200, body = inline(CommonApiResp<Vec<FlowConfig>>)))
)]
async fn get_flow_rules(State(state): State<LandscapeApp>) -> LandscapeApiResult<Vec<FlowConfig>> {
    let mut result = state.flow_rule_service.list().await;
    result.sort_by(|a, b| a.flow_id.cmp(&b.flow_id));
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/rules/flow_id/{id}",
    tag = "Flow Rules",
    params(("id" = u32, Path, description = "Flow ID")),
    responses(
        (status = 200, body = inline(CommonApiResp<FlowConfig>)),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    get,
    path = "/rules/{id}",
    tag = "Flow Rules",
    params(("id" = Uuid, Path, description = "Flow rule config ID")),
    responses(
        (status = 200, body = inline(CommonApiResp<FlowConfig>)),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    post,
    path = "/rules",
    tag = "Flow Rules",
    request_body = FlowConfig,
    responses((status = 200, body = inline(CommonApiResp<FlowConfig>)))
)]
async fn add_flow_rule(
    State(state): State<LandscapeApp>,
    JsonBody(flow_rule): JsonBody<FlowConfig>,
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

#[utoipa::path(
    delete,
    path = "/rules/{id}",
    tag = "Flow Rules",
    params(("id" = Uuid, Path, description = "Flow rule config ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_flow_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.flow_rule_service.delete(id).await;
    LandscapeApiResp::success(())
}
