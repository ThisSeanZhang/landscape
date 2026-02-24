use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{dns::DNSRuleConfig, ConfigId, FlowId};
use landscape_common::service::controller_service_v2::ConfigController;
use landscape_common::service::controller_service_v2::FlowConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::config::dns::DnsRuleError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dns_rule_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_dns_rules, add_dns_rules))
        .routes(routes!(add_many_dns_rules))
        .routes(routes!(get_dns_rule, del_dns_rules))
        .routes(routes!(get_flow_dns_rules))
}

#[utoipa::path(
    get,
    path = "/rules",
    tag = "DNS Rules",
    responses((status = 200, body = CommonApiResp<Vec<DNSRuleConfig>>))
)]
async fn get_dns_rules(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DNSRuleConfig>> {
    let result = state.dns_rule_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/rules/flow/{flow_id}",
    tag = "DNS Rules",
    params(("flow_id" = u32, Path, description = "Flow ID")),
    responses((status = 200, body = CommonApiResp<Vec<DNSRuleConfig>>))
)]
async fn get_flow_dns_rules(
    State(state): State<LandscapeApp>,
    Path(id): Path<FlowId>,
) -> LandscapeApiResult<Vec<DNSRuleConfig>> {
    let mut result = state.dns_rule_service.list_flow_configs(id).await;
    result.sort_by(|a, b| a.index.cmp(&b.index));
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/rules/{id}",
    tag = "DNS Rules",
    params(("id" = Uuid, Path, description = "DNS rule ID")),
    responses(
        (status = 200, body = CommonApiResp<DNSRuleConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_dns_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DNSRuleConfig> {
    let result = state.dns_rule_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(DnsRuleError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/rules/batch",
    tag = "DNS Rules",
    request_body = Vec<DNSRuleConfig>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_dns_rules(
    State(state): State<LandscapeApp>,
    JsonBody(dns_rules): JsonBody<Vec<DNSRuleConfig>>,
) -> LandscapeApiResult<()> {
    state.dns_rule_service.set_list(dns_rules).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/rules",
    tag = "DNS Rules",
    request_body = DNSRuleConfig,
    responses((status = 200, body = CommonApiResp<DNSRuleConfig>))
)]
async fn add_dns_rules(
    State(state): State<LandscapeApp>,
    JsonBody(dns_rule): JsonBody<DNSRuleConfig>,
) -> LandscapeApiResult<DNSRuleConfig> {
    let result = state.dns_rule_service.set(dns_rule).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    delete,
    path = "/rules/{id}",
    tag = "DNS Rules",
    params(("id" = Uuid, Path, description = "DNS rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_dns_rules(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.dns_rule_service.delete(id).await;
    LandscapeApiResp::success(())
}
