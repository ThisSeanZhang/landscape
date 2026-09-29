use std::{collections::HashMap, net::IpAddr};

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::service::controller::ControllerService;
use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::wan_service::ip_config::{IfaceIpModelConfig, IfaceIpServiceConfig};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape::netlink::address::addresses_by_iface_name;
use landscape_common::service::ServiceConfigError;
use serde::Serialize;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

#[derive(Debug, Serialize, utoipa::ToSchema)]
struct RuntimeIpAddress {
    #[schema(value_type = String)]
    address: IpAddr,
    prefix_length: u8,
    is_permanent: bool,
}

async fn validate_ip_config(
    state: &LandscapeApp,
    config: &IfaceIpServiceConfig,
) -> Result<(), ServiceConfigError> {
    if config.enable && matches!(&config.ip_model, IfaceIpModelConfig::PPPoE { .. }) {
        let attached_pppds = state
            .pppd_service
            .get_pppd_configs_by_attach_iface_name(config.iface_name.clone())
            .await;
        if !attached_pppds.is_empty() {
            return Err(ServiceConfigError::InvalidConfig {
                reason: format!(
                    "Interface '{}' already has PPPD-based PPPoE configured; remove it before enabling native PPPoE",
                    config.iface_name
                ),
            });
        }
    }

    Ok(())
}

pub fn get_iface_ipconfig_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_ipconfig_status))
        .routes(routes!(get_runtime_ip_addresses))
        .routes(routes!(handle_iface_service_status))
        .routes(routes!(get_iface_service_config, delete_and_stop_iface_service))
}

#[utoipa::path(
    get,
    path = "/ip/runtime-addresses/{iface_name}",
    tag = "IP Config",
    operation_id = "get_runtime_ip_addresses",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<RuntimeIpAddress>>))
)]
async fn get_runtime_ip_addresses(
    State(_state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Vec<RuntimeIpAddress>> {
    if iface_name == "lo" {
        return LandscapeApiResp::success(Vec::new());
    }

    LandscapeApiResp::success(
        addresses_by_iface_name(iface_name)
            .await
            .into_iter()
            .map(|address| RuntimeIpAddress {
                address: address.address,
                prefix_length: address.prefix_len,
                is_permanent: address.is_permanent,
            })
            .collect(),
    )
}

#[utoipa::path(
    get,
    path = "/ip/status",
    tag = "IP Config",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_ipconfig_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, WatchService>> {
    LandscapeApiResp::success(state.wan_ip_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/ip/{iface_name}",
    tag = "IP Config",
    operation_id = "get_ipconfig_service_config",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<IfaceIpServiceConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_service_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<IfaceIpServiceConfig> {
    if let Some(iface_config) = state.wan_ip_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(ServiceConfigError::NotFound { service_name: "Iface Ip" })?
    }
}

#[utoipa::path(
    put,
    path = "/ip",
    tag = "IP Config",
    request_body = IfaceIpServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_iface_service_status(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<IfaceIpServiceConfig>,
) -> LandscapeApiResult<()> {
    validate_ip_config(&state, &config).await?;
    state.validate_zone(&config).await?;
    state.wan_ip_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/ip/{iface_name}",
    tag = "IP Config",
    operation_id = "delete_and_stop_ipconfig_service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success", body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_and_stop_iface_service(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<WatchService>> {
    LandscapeApiResp::success(state.wan_ip_service.delete_and_stop_iface_service(iface_name).await)
}
