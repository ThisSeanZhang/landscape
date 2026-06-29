use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::database::LandscapeStore;
use landscape_common::iface::ip_config::IfaceIpModelConfig;
use landscape_common::iface::ppp::{validate_ppp_iface_name, PPPDServiceConfig};
use landscape_common::service::controller::{ConfigController, ControllerService};
use landscape_common::service::{ServiceStatus, WatchService};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::service::ServiceConfigError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

async fn validate_pppd_config(
    state: &LandscapeApp,
    config: &PPPDServiceConfig,
) -> Result<(), ServiceConfigError> {
    validate_ppp_iface_name(&config.iface_name)?;

    if config.iface_name == config.attach_iface_name {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "PPPoE interface name cannot be the same as its attached interface".to_string(),
        });
    }

    if state.pppd_service.get_config_by_name(config.attach_iface_name.clone()).await.is_some() {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!(
                "PPPoE attach interface '{}' cannot be an existing PPP interface",
                config.attach_iface_name
            ),
        });
    }

    let existing_pppd = state.pppd_service.get_config_by_name(config.iface_name.clone()).await;
    let managed_iface_exists =
        state.iface_config_service.get_iface_config(config.iface_name.clone()).await.is_some();
    let live_iface_exists = landscape::get_iface_by_name(&config.iface_name).await.is_some();
    if existing_pppd.is_none() && (managed_iface_exists || live_iface_exists) {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!(
                "PPPoE interface '{}' conflicts with an existing interface",
                config.iface_name
            ),
        });
    }

    if config.enable {
        if let Some(ip_config) =
            state.wan_ip_service.get_config_by_name(config.attach_iface_name.clone()).await
        {
            if ip_config.enable && matches!(ip_config.ip_model, IfaceIpModelConfig::PPPoE { .. }) {
                return Err(ServiceConfigError::InvalidConfig {
                    reason: format!(
                        "Interface '{}' already uses native PPPoE in IP Config; disable it before enabling PPPD-based PPPoE",
                        config.attach_iface_name
                    ),
                });
            }
        }
    }

    Ok(())
}

async fn delete_ppp_iface(state: &LandscapeApp, iface_name: &str) -> Option<WatchService> {
    state.remove_direct_iface_service(iface_name).await;
    state.iface_config_service.delete(iface_name.to_string()).await;
    state.pppd_service.delete_and_stop_pppd(iface_name.to_string()).await
}

pub(crate) async fn delete_ppp_ifaces_by_attach_name(state: &LandscapeApp, attach_name: &str) {
    let configs =
        state.pppd_service.get_pppd_configs_by_attach_iface_name(attach_name.to_string()).await;
    for config in configs {
        delete_ppp_iface(state, &config.iface_name).await;
    }
}

pub fn get_iface_pppd_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_pppd_configs, handle_iface_pppd_config))
        .routes(routes!(
            get_iface_pppd_config,
            update_existing_iface_pppd_config,
            delete_and_stop_iface_pppd
        ))
        .routes(routes!(get_all_pppd_status))
        .routes(routes!(
            get_iface_pppd_config_by_attach_iface_name,
            delete_and_stop_iface_pppd_by_attach_iface_name
        ))
}

#[utoipa::path(
    get,
    path = "/pppoe",
    tag = "PPPoE",
    responses((status = 200, body = CommonApiResp<Vec<PPPDServiceConfig>>))
)]
async fn get_all_pppd_configs(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<PPPDServiceConfig>> {
    LandscapeApiResp::success(state.pppd_service.get_repository().list().await.unwrap_or_default())
}

#[utoipa::path(
    get,
    path = "/pppoe/status",
    tag = "PPPoE",
    responses((status = 200, body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_pppd_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, WatchService>> {
    LandscapeApiResp::success(state.pppd_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/pppoe/attach/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Attach interface name")),
    responses((status = 200, body = CommonApiResp<Vec<PPPDServiceConfig>>))
)]
async fn get_iface_pppd_config_by_attach_iface_name(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Vec<PPPDServiceConfig>> {
    let configs = state.pppd_service.get_pppd_configs_by_attach_iface_name(iface_name).await;

    LandscapeApiResp::success(configs)
}

#[utoipa::path(
    get,
    path = "/pppoe/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, body = CommonApiResp<PPPDServiceConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_pppd_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<PPPDServiceConfig> {
    if let Some(iface_config) = state.pppd_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "PPPD" })?
    }
}

#[utoipa::path(
    put,
    path = "/pppoe",
    tag = "PPPoE",
    request_body = PPPDServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_iface_pppd_config(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<PPPDServiceConfig>,
) -> LandscapeApiResult<()> {
    validate_pppd_config(&state, &config).await?;
    if state.pppd_service.get_config_by_name(config.iface_name.clone()).await.is_some() {
        return Err(ServiceConfigError::InvalidConfig {
            reason: format!(
                "PPPoE interface '{}' already exists; update it via its current interface name",
                config.iface_name
            ),
        })?;
    }
    state.validate_zone(&config).await?;
    config.pppd_config.validate()?;
    state.pppd_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    put,
    path = "/pppoe/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Existing PPP interface name")),
    request_body = PPPDServiceConfig,
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn update_existing_iface_pppd_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
    JsonBody(config): JsonBody<PPPDServiceConfig>,
) -> LandscapeApiResult<()> {
    if state.pppd_service.get_config_by_name(iface_name.clone()).await.is_none() {
        return Err(ServiceConfigError::NotFound { service_name: "PPPD" })?;
    }

    if config.iface_name != iface_name {
        return Err(ServiceConfigError::InvalidConfig {
            reason: "Established PPPoE interfaces cannot be renamed".to_string(),
        })?;
    }

    validate_pppd_config(&state, &config).await?;
    state.validate_zone(&config).await?;
    config.pppd_config.validate()?;
    state.pppd_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/pppoe/attach/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Attach interface name")),
    responses((status = 200, description = "Success"))
)]
async fn delete_and_stop_iface_pppd_by_attach_iface_name(
    State(state): State<LandscapeApp>,
    Path(attach_name): Path<String>,
) -> LandscapeApiResult<()> {
    delete_ppp_ifaces_by_attach_name(&state, &attach_name).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/pppoe/{iface_name}",
    tag = "PPPoE",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_and_stop_iface_pppd(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<WatchService>> {
    LandscapeApiResp::success(delete_ppp_iface(&state, &iface_name).await)
}
