use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::firewall::blacklist::FirewallBlacklistConfig;
use landscape_common::service::controller_service_v2::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::firewall::blacklist::FirewallBlacklistError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_firewall_blacklist_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_firewall_blacklists, add_firewall_blacklist))
        .routes(routes!(get_firewall_blacklist, del_firewall_blacklist))
}

#[utoipa::path(
    get,
    path = "/blacklists",
    tag = "Firewall Blacklists",
    responses((status = 200, body = CommonApiResp<Vec<FirewallBlacklistConfig>>))
)]
async fn get_firewall_blacklists(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<FirewallBlacklistConfig>> {
    let result = state.firewall_blacklist_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/blacklists/{id}",
    tag = "Firewall Blacklists",
    params(("id" = Uuid, Path, description = "Firewall blacklist ID")),
    responses(
        (status = 200, body = CommonApiResp<FirewallBlacklistConfig>),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    post,
    path = "/blacklists",
    tag = "Firewall Blacklists",
    request_body = FirewallBlacklistConfig,
    responses((status = 200, body = CommonApiResp<FirewallBlacklistConfig>))
)]
async fn add_firewall_blacklist(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<FirewallBlacklistConfig>,
) -> LandscapeApiResult<FirewallBlacklistConfig> {
    let result = state.firewall_blacklist_service.set(config).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    delete,
    path = "/blacklists/{id}",
    tag = "Firewall Blacklists",
    params(("id" = Uuid, Path, description = "Firewall blacklist ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_firewall_blacklist(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.firewall_blacklist_service.delete(id).await;
    LandscapeApiResp::success(())
}
