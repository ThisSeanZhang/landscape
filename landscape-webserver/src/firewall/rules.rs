use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::firewall::FirewallRuleConfig;
use landscape_common::service::controller_service_v2::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::firewall::FirewallRuleError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_firewall_rule_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_firewall_rules, add_firewall_rule))
        .routes(routes!(get_firewall_rule, del_firewall_rule))
}

#[utoipa::path(
    get,
    path = "/rules",
    tag = "Firewall Rules",
    responses((status = 200, body = inline(CommonApiResp<Vec<FirewallRuleConfig>>)))
)]
async fn get_firewall_rules(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<FirewallRuleConfig>> {
    let mut result = state.fire_wall_rule_service.list().await;
    result.sort_by(|a, b| a.index.cmp(&b.index));
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/rules/{id}",
    tag = "Firewall Rules",
    params(("id" = Uuid, Path, description = "Firewall rule ID")),
    responses(
        (status = 200, body = inline(CommonApiResp<FirewallRuleConfig>)),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    post,
    path = "/rules",
    tag = "Firewall Rules",
    request_body = FirewallRuleConfig,
    responses((status = 200, body = inline(CommonApiResp<FirewallRuleConfig>)))
)]
async fn add_firewall_rule(
    State(state): State<LandscapeApp>,
    JsonBody(firewall_rule): JsonBody<FirewallRuleConfig>,
) -> LandscapeApiResult<FirewallRuleConfig> {
    let result = state.fire_wall_rule_service.set(firewall_rule).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    delete,
    path = "/rules/{id}",
    tag = "Firewall Rules",
    params(("id" = Uuid, Path, description = "Firewall rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_firewall_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.fire_wall_rule_service.delete(id).await;
    LandscapeApiResp::success(())
}
