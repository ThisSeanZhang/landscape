use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape::get_iface_by_name;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::service::ServiceConfigError;
use landscape_common::wan_service::link::{
    check_link_cardinality, check_ppp_iface_name_unique, LinkStatus, WanLinkConfig,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_wan_links_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_links))
        .routes(routes!(get_link_statuses))
        .routes(routes!(handle_link_config))
        .routes(routes!(get_link_config, delete_link))
}

#[utoipa::path(
    get,
    path = "/wan-links",
    tag = "WAN Links",
    operation_id = "get_all_wan_links",
    responses((status = 200, body = CommonApiResp<Vec<WanLinkConfig>>))
)]
async fn get_all_links(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<WanLinkConfig>> {
    LandscapeApiResp::success(state.wan_link_service.list_links().await)
}

#[utoipa::path(
    get,
    path = "/wan-links/status",
    tag = "WAN Links",
    operation_id = "get_wan_link_statuses",
    responses((status = 200, body = CommonApiResp<HashMap<String, LinkStatus>>))
)]
async fn get_link_statuses(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, LinkStatus>> {
    LandscapeApiResp::success(state.wan_link_service.get_link_statuses().await)
}

#[utoipa::path(
    get,
    path = "/wan-links/{id}",
    tag = "WAN Links",
    operation_id = "get_wan_link_config",
    params(("id" = Uuid, Path, description = "Link id")),
    responses(
        (status = 200, body = CommonApiResp<WanLinkConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_link_config(
    State(state): State<LandscapeApp>,
    Path(id): Path<Uuid>,
) -> LandscapeApiResult<WanLinkConfig> {
    if let Some(config) = state.wan_link_service.get_config_by_id(id).await {
        LandscapeApiResp::success(config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "WAN Link" })?
    }
}

#[utoipa::path(
    put,
    path = "/wan-links",
    tag = "WAN Links",
    operation_id = "handle_wan_link_config",
    request_body = WanLinkConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_link_config(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<WanLinkConfig>,
) -> LandscapeApiResult<()> {
    config.validate()?;
    state.validate_zone(&config).await?;
    check_attach_mac(&config).await?;
    check_cardinality(&state, &config).await?;
    state.wan_link_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/wan-links/{id}",
    tag = "WAN Links",
    operation_id = "delete_wan_link",
    params(("id" = Uuid, Path, description = "Link id")),
    responses((status = 200, description = "Success"))
)]
async fn delete_link(
    State(state): State<LandscapeApp>,
    Path(id): Path<Uuid>,
) -> LandscapeApiResult<()> {
    state.wan_link_service.delete_and_stop_iface_service(id).await;
    LandscapeApiResp::success(())
}

async fn check_cardinality(
    state: &LandscapeApp,
    config: &WanLinkConfig,
) -> Result<(), ServiceConfigError> {
    // The wan_links table is tiny; fetch everything once and split in memory.
    let all = state.wan_link_service.list_links().await;
    let others: Vec<WanLinkConfig> = all
        .iter()
        .filter(|link| link.attach_iface_name == config.attach_iface_name)
        .cloned()
        .collect();
    check_link_cardinality(config, &others)?;
    check_ppp_iface_name_unique(config, &all)
}

/// Reject, at save time, links whose session kind needs an attach MAC that the
/// interface does not expose. Strict: a missing/unfindable attach iface is also
/// rejected here (the runtime never has to guess).
async fn check_attach_mac(config: &WanLinkConfig) -> Result<(), ServiceConfigError> {
    if !config.requires_attach_mac() {
        return Ok(());
    }
    let iface_name = &config.attach_iface_name;
    match get_iface_by_name(iface_name).await {
        Some(iface) if iface.mac.is_some() => Ok(()),
        Some(_) => Err(ServiceConfigError::InvalidConfig {
            reason: format!(
                "attach iface '{iface_name}' has no MAC address; required for PPPoE/DHCP"
            ),
        }),
        None => Err(ServiceConfigError::IfaceNotFound { iface_name: iface_name.clone() }),
    }
}
