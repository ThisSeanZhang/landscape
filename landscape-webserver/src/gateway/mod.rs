use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::service::ServiceStatus;
use landscape_common::sys_service::gateway::{GatewayError, HttpUpstreamRuleConfig};
use serde::Serialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{
    api::LandscapeApiResp,
    error::{LandscapeApiError, LandscapeApiResult},
};

pub fn get_gateway_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(list_gateway_rules, create_gateway_rule))
        .routes(routes!(get_gateway_rule, delete_gateway_rule))
        .routes(routes!(get_gateway_status, restart_gateway))
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct GatewayStatus {
    pub supported: bool,
    pub status: ServiceStatus,
    pub http_port: u16,
    pub https_port: u16,
    pub https_ready: bool,
    pub rule_count: usize,
}

#[utoipa::path(
    get,
    path = "/rules",
    tag = "Gateway",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<HttpUpstreamRuleConfig>>))
)]
async fn list_gateway_rules(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<HttpUpstreamRuleConfig>> {
    ensure_gateway_supported(&state)?;
    let result = state.managed.gateway_service.list_rules().await.unwrap_or_default();
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/rules",
    tag = "Gateway",
    request_body = HttpUpstreamRuleConfig,
    responses((status = 200, description = "Success", body = CommonApiResp<HttpUpstreamRuleConfig>))
)]
async fn create_gateway_rule(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<HttpUpstreamRuleConfig>,
) -> LandscapeApiResult<HttpUpstreamRuleConfig> {
    ensure_gateway_supported(&state)?;

    let saved = state.managed.gateway_service.save_rule(config).await?;

    LandscapeApiResp::success(saved)
}

#[utoipa::path(
    get,
    path = "/rules/{id}",
    tag = "Gateway",
    params(("id" = Uuid, Path, description = "Gateway rule ID")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<HttpUpstreamRuleConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_gateway_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<HttpUpstreamRuleConfig> {
    ensure_gateway_supported(&state)?;
    let result = state.managed.gateway_service.find_rule(id).await?;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(GatewayError::NotFound(id))?
    }
}

#[utoipa::path(
    delete,
    path = "/rules/{id}",
    tag = "Gateway",
    params(("id" = Uuid, Path, description = "Gateway rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn delete_gateway_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    ensure_gateway_supported(&state)?;
    state.managed.gateway_service.delete_rule(id).await?;

    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/status",
    tag = "Gateway",
    responses((status = 200, description = "Success", body = CommonApiResp<GatewayStatus>))
)]
async fn get_gateway_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<GatewayStatus> {
    LandscapeApiResp::success(build_gateway_status(&state).await)
}

#[utoipa::path(
    post,
    path = "/restart",
    tag = "Gateway",
    responses((status = 200, description = "Success", body = CommonApiResp<GatewayStatus>))
)]
async fn restart_gateway(State(state): State<LandscapeApp>) -> LandscapeApiResult<GatewayStatus> {
    ensure_gateway_supported(&state)?;
    let gateway_config = state.system.config_service.get_gateway_runtime_config();
    state.managed.gateway_service.restart(gateway_config, std::time::Duration::from_secs(10)).await;
    LandscapeApiResp::success(build_gateway_status(&state).await)
}

async fn build_gateway_status(state: &LandscapeApp) -> GatewayStatus {
    let config = state.managed.gateway_service.config();
    GatewayStatus {
        supported: state.managed.gateway_service.is_supported(),
        status: state.managed.gateway_service.status(),
        http_port: config.http_port,
        https_port: config.https_port,
        https_ready: state.managed.gateway_service.has_https_listener(),
        rule_count: state.managed.gateway_service.stored_rule_count().await,
    }
}

fn ensure_gateway_supported(state: &LandscapeApp) -> Result<(), LandscapeApiError> {
    if state.managed.gateway_service.is_supported() {
        Ok(())
    } else {
        Err(LandscapeApiError::GatewayUnsupportedTarget)
    }
}
