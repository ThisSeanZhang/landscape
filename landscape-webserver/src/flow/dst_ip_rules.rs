use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{ConfigId, FlowId};
use landscape_common::flow::ip_mark::WanIpRuleConfig;
use landscape_common::service::controller::{ConfigController, FlowConfigController};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::flow::ip_mark::DstIpRuleError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dst_ip_rule_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_dst_ip_rules, add_dst_ip_rules))
        .routes(routes!(add_many_dst_ip_rules))
        .routes(routes!(get_dst_ip_rule, modify_dst_ip_rules, del_dst_ip_rule))
        .routes(routes!(get_flow_dst_ip_rules))
}

async fn ensure_flow_id_unchanged(
    state: &LandscapeApp,
    config: &WanIpRuleConfig,
) -> Result<(), DstIpRuleError> {
    if let Some(existing) = state.dst_ip_rule_service.find_by_id(config.id).await {
        if existing.flow_id != config.flow_id {
            return Err(DstIpRuleError::CannotChangeFlow(config.id));
        }
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/dst_ip_rules",
    tag = "Destination IP Rules",
    responses((status = 200, body = CommonApiResp<Vec<WanIpRuleConfig>>))
)]
async fn get_dst_ip_rules(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<WanIpRuleConfig>> {
    let result = state.dst_ip_rule_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/dst_ip_rules/flow/{flow_id}",
    tag = "Destination IP Rules",
    params(("flow_id" = u32, Path, description = "Flow ID")),
    responses((status = 200, body = CommonApiResp<Vec<WanIpRuleConfig>>))
)]
async fn get_flow_dst_ip_rules(
    State(state): State<LandscapeApp>,
    Path(id): Path<FlowId>,
) -> LandscapeApiResult<Vec<WanIpRuleConfig>> {
    let mut result = state.dst_ip_rule_service.list_flow_configs(id).await;
    result.sort_by_key(|a| a.index);
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/dst_ip_rules/{id}",
    tag = "Destination IP Rules",
    params(("id" = Uuid, Path, description = "Destination IP rule ID")),
    responses(
        (status = 200, body = CommonApiResp<WanIpRuleConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_dst_ip_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<WanIpRuleConfig> {
    let result = state.dst_ip_rule_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(DstIpRuleError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/dst_ip_rules/{id}",
    tag = "Destination IP Rules",
    params(("id" = Uuid, Path, description = "Destination IP rule ID")),
    request_body = WanIpRuleConfig,
    responses((status = 200, body = CommonApiResp<WanIpRuleConfig>))
)]
async fn modify_dst_ip_rules(
    State(state): State<LandscapeApp>,
    Path(_id): Path<ConfigId>,
    JsonBody(rule): JsonBody<WanIpRuleConfig>,
) -> LandscapeApiResult<WanIpRuleConfig> {
    ensure_flow_id_unchanged(&state, &rule).await?;
    let result = state.dst_ip_rule_service.checked_set(rule).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/dst_ip_rules",
    tag = "Destination IP Rules",
    request_body = WanIpRuleConfig,
    responses((status = 200, body = CommonApiResp<WanIpRuleConfig>))
)]
async fn add_dst_ip_rules(
    State(state): State<LandscapeApp>,
    JsonBody(rule): JsonBody<WanIpRuleConfig>,
) -> LandscapeApiResult<WanIpRuleConfig> {
    ensure_flow_id_unchanged(&state, &rule).await?;
    let result = state.dst_ip_rule_service.checked_set(rule).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/dst_ip_rules/batch",
    tag = "Destination IP Rules",
    request_body = Vec<WanIpRuleConfig>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_dst_ip_rules(
    State(state): State<LandscapeApp>,
    JsonBody(rules): JsonBody<Vec<WanIpRuleConfig>>,
) -> LandscapeApiResult<()> {
    for rule in &rules {
        ensure_flow_id_unchanged(&state, rule).await?;
    }
    state.dst_ip_rule_service.checked_set_list(rules).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/dst_ip_rules/{id}",
    tag = "Destination IP Rules",
    params(("id" = Uuid, Path, description = "Destination IP rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_dst_ip_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.dst_ip_rule_service.delete(id).await;
    LandscapeApiResp::success(())
}
