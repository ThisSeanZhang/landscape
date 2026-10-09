use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::service::ServiceConfigError;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::wan_link::{
    CreateWanLinkConfig, UpdateWanLinkConfig, WanLinkConfig, WanLinkKind, WanLinkStatus,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::{LandscapeApp, api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_wan_link_paths() -> OpenApiRouter<LandscapeApp> {
    // utoipa_axum 0.3: one `routes!` invocation per path — every handler in
    // a call is folded onto the same MethodRouter.
    OpenApiRouter::new()
        .routes(routes!(list_wan_links, create_wan_link))
        .routes(routes!(get_all_wan_link_status))
        .routes(routes!(get_wan_link, update_wan_link, delete_wan_link))
}

#[utoipa::path(
    get,
    path = "/wan-links",
    tag = "WAN Link",
    operation_id = "list_wan_links",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<WanLinkConfig>>))
)]
async fn list_wan_links(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<WanLinkConfig>> {
    LandscapeApiResp::success(state.wan_link_service.list().await?)
}

#[utoipa::path(
    get,
    path = "/wan-links/status",
    tag = "WAN Link",
    operation_id = "get_all_wan_link_status",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, WanLinkStatus>>))
)]
async fn get_all_wan_link_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, WanLinkStatus>> {
    LandscapeApiResp::success(state.wan_link_service.get_link_statuses().await)
}

#[utoipa::path(
    get,
    path = "/wan-links/{id}",
    tag = "WAN Link",
    operation_id = "get_wan_link",
    params(("id" = Uuid, Path, description = "WAN link ID")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<WanLinkConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_wan_link(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<WanLinkConfig> {
    if let Some(link) = state.wan_link_service.find_by_id(id).await? {
        LandscapeApiResp::success(link)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "WAN Link" })?
    }
}

#[utoipa::path(
    post,
    path = "/wan-links",
    tag = "WAN Link",
    operation_id = "create_wan_link",
    request_body = CreateWanLinkConfig,
    responses((status = 200, description = "Success", body = CommonApiResp<WanLinkConfig>))
)]
async fn create_wan_link(
    State(state): State<LandscapeApp>,
    JsonBody(payload): JsonBody<CreateWanLinkConfig>,
) -> LandscapeApiResult<WanLinkConfig> {
    // id/update_at are server-assigned by the DTO conversion.
    let payload: WanLinkConfig = payload.into();
    validate_wan_link(&payload, None).await?;
    LandscapeApiResp::success(state.wan_link_service.handle_service_config(payload).await?)
}

#[utoipa::path(
    put,
    path = "/wan-links/{id}",
    tag = "WAN Link",
    operation_id = "update_wan_link",
    params(("id" = Uuid, Path, description = "WAN link ID")),
    request_body = UpdateWanLinkConfig,
    responses(
        (status = 200, description = "Success", body = CommonApiResp<WanLinkConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn update_wan_link(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(body): JsonBody<UpdateWanLinkConfig>,
) -> LandscapeApiResult<WanLinkConfig> {
    let old = state.wan_link_service.find_by_id(id).await?;
    if old.is_none() {
        Err(ServiceConfigError::NotFound { service_name: "WAN Link" })?;
    }
    // Path id wins; update_at must echo the client's last-seen version.
    let mut payload: WanLinkConfig = body.into();
    payload.id = id;
    validate_wan_link(&payload, old.as_ref()).await?;
    LandscapeApiResp::success(state.wan_link_service.handle_service_config(payload).await?)
}

#[utoipa::path(
    delete,
    path = "/wan-links/{id}",
    tag = "WAN Link",
    operation_id = "delete_wan_link",
    params(("id" = Uuid, Path, description = "WAN link ID")),
    responses((status = 200, description = "Success", body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_wan_link(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<Option<ServiceStatus>> {
    if let Some(config) = state.wan_link_service.find_by_id(id).await?
        && matches!(config.kind, WanLinkKind::Pppd { .. })
        && config.v4.enable
    {
        // Legacy guard: an enabled PPPD link must be disabled before delete.
        Err(ServiceConfigError::InvalidConfig {
            reason: "disable the PPPD link before deleting it".to_string(),
        })?;
    }
    LandscapeApiResp::success(state.wan_link_service.delete_and_stop_service(id).await?)
}

/// Runtime-state (netlink) validation only. Cross-link rules and the WAN
/// zone check live in `WanLinkRepository`'s `StoreValidator`, injected
/// into the checked write path; section-level rules live in
/// `ValidatableConfig for WanLinkConfig`. `old` is the stored config when
/// updating.
async fn validate_wan_link(
    config: &WanLinkConfig,
    old: Option<&WanLinkConfig>,
) -> Result<(), ServiceConfigError> {
    if landscape::get_iface_by_name(&config.attach_iface_name).await.is_none() {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!("attach interface '{}' not found", config.attach_iface_name),
        });
    }

    // A new ppp device must not collide with a live interface; an unchanged
    // ppp_iface_name is skipped: the live interface is the link's own ppp
    // device (created by its pppd).
    if let WanLinkKind::Pppd { ppp_iface_name, .. } = &config.kind {
        let unchanged_name = old.is_some_and(|old| {
            matches!(&old.kind, WanLinkKind::Pppd { ppp_iface_name: n, .. } if n == ppp_iface_name)
        });
        if !unchanged_name && landscape::get_iface_by_name(ppp_iface_name).await.is_some() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "PPPoE interface '{ppp_iface_name}' conflicts with an existing interface"
                ),
            });
        }
    }

    Ok(())
}
