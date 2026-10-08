use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::config_service::iface::IfaceZoneType;
use landscape_common::service::ServiceConfigError;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::wan_link::{WanLinkConfig, WanLinkKind};
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
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_wan_link_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, ServiceStatus>> {
    LandscapeApiResp::success(state.wan_link_service.get_all_status().await)
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
    request_body = WanLinkConfig,
    responses((status = 200, description = "Success", body = CommonApiResp<WanLinkConfig>))
)]
async fn create_wan_link(
    State(state): State<LandscapeApp>,
    JsonBody(mut payload): JsonBody<WanLinkConfig>,
) -> LandscapeApiResult<WanLinkConfig> {
    // The id is always server-assigned; a client-supplied one is ignored.
    payload.id = ConfigId::new_v4();
    validate_wan_link(&state, &payload, None).await?;
    LandscapeApiResp::success(state.wan_link_service.handle_service_config(payload).await?)
}

#[utoipa::path(
    put,
    path = "/wan-links/{id}",
    tag = "WAN Link",
    operation_id = "update_wan_link",
    params(("id" = Uuid, Path, description = "WAN link ID")),
    request_body = WanLinkConfig,
    responses(
        (status = 200, description = "Success", body = CommonApiResp<WanLinkConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn update_wan_link(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(mut payload): JsonBody<WanLinkConfig>,
) -> LandscapeApiResult<WanLinkConfig> {
    if state.wan_link_service.find_by_id(id).await?.is_none() {
        Err(ServiceConfigError::NotFound { service_name: "WAN Link" })?
    }
    payload.id = id;
    validate_wan_link(&state, &payload, Some(id)).await?;
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

/// Cross-link validation: section-level rules live in
/// `ValidatableConfig for WanLinkConfig` (store write path); everything
/// that needs the link set or the iface inventory is checked here.
/// `exclude_id` skips the link being updated.
async fn validate_wan_link(
    state: &LandscapeApp,
    config: &WanLinkConfig,
    exclude_id: Option<ConfigId>,
) -> Result<(), ServiceConfigError> {
    if landscape::get_iface_by_name(&config.attach_iface_name).await.is_none() {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!("attach interface '{}' not found", config.attach_iface_name),
        });
    }

    // Legacy ZoneAwareConfig (WanOnly) semantics: links only live on WAN
    // ifaces; the zone-switch cascade deletes links, keeping both in sync.
    match state.iface_config_service.get_iface_config(config.attach_iface_name.clone()).await {
        Some(iface) if iface.zone_type == IfaceZoneType::Wan => {}
        _ => {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "attach interface '{}' must be in the WAN zone",
                    config.attach_iface_name
                ),
            });
        }
    }

    let links = state.wan_link_service.list().await.unwrap_or_default();
    let others: Vec<&WanLinkConfig> =
        links.iter().filter(|link| Some(link.id) != exclude_id).collect();

    fn is_ethernet_class(kind: &WanLinkKind) -> bool {
        !matches!(kind, WanLinkKind::Pppd { .. })
    }

    for link in &others {
        if link.attach_iface_name == config.attach_iface_name {
            // At most one ethernet-class link (ethernet / pppoe_native) per
            // attach iface; PPPD links may stack alongside.
            if is_ethernet_class(&config.kind) && is_ethernet_class(&link.kind) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "attach interface '{}' already has an ethernet-class WAN link",
                        config.attach_iface_name
                    ),
                });
            }
            // Native PPPoE and PPPD cannot share an attach iface (legacy rule).
            if (matches!(config.kind, WanLinkKind::Pppd { .. })
                && matches!(link.kind, WanLinkKind::PppoeNative { .. }))
                || (matches!(config.kind, WanLinkKind::PppoeNative { .. })
                    && matches!(link.kind, WanLinkKind::Pppd { .. }))
            {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "interface '{}' already uses native PPPoE; disable it before enabling PPPD-based PPPoE",
                        config.attach_iface_name
                    ),
                });
            }
        }

        if let (
            WanLinkKind::Pppd { ppp_iface_name, .. },
            WanLinkKind::Pppd { ppp_iface_name: existing, .. },
        ) = (&config.kind, &link.kind)
            && ppp_iface_name == existing
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!("PPPoE interface name '{ppp_iface_name}' is already in use"),
            });
        }

        // The attach iface itself must not be another link's ppp device.
        if let WanLinkKind::Pppd { ppp_iface_name, .. } = &link.kind
            && *ppp_iface_name == config.attach_iface_name
        {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "attach interface '{}' cannot be an existing PPP interface",
                    config.attach_iface_name
                ),
            });
        }
    }

    // A new ppp device must not collide with a managed or live interface.
    if let WanLinkKind::Pppd { ppp_iface_name, .. } = &config.kind {
        let existing_pppd = others.iter().any(|link| {
            matches!(&link.kind, WanLinkKind::Pppd { ppp_iface_name: n, .. } if n == ppp_iface_name)
        });
        let managed_iface_exists =
            state.iface_config_service.get_iface_config(ppp_iface_name.clone()).await.is_some();
        let live_iface_exists = landscape::get_iface_by_name(ppp_iface_name).await.is_some();
        if !existing_pppd && (managed_iface_exists || live_iface_exists) {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "PPPoE interface '{ppp_iface_name}' conflicts with an existing interface"
                ),
            });
        }
    }

    Ok(())
}
