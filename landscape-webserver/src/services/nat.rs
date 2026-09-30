use std::collections::HashMap;

use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::ConfigStoreServiceController;
use landscape_common::wan_service::nat::config::NatServiceConfig;
use landscape_common::wan_service::nat::error::NatServiceError;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_iface_nat_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_nat_status))
        .routes(routes!(handle_iface_nat_status))
        .routes(routes!(get_iface_nat_config, delete_and_stop_iface_nat))
}

#[utoipa::path(
    get,
    path = "/nat/status",
    tag = "NAT Service",
    responses((status = 200, description = "Success", body = CommonApiResp<HashMap<String, ServiceStatus>>))
)]
async fn get_all_nat_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, ServiceStatus>> {
    LandscapeApiResp::success(state.nat_service.get_all_status().await)
}

#[utoipa::path(
    get,
    path = "/nat/{iface_name}",
    tag = "NAT Service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<NatServiceConfig>),
        (status = 404, description = "Not found")
    )
)]
async fn get_iface_nat_config(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<NatServiceConfig> {
    let key = iface_name.clone();
    if let Some(iface_config) = state.nat_service.get_config_by_name(iface_name).await {
        LandscapeApiResp::success(iface_config)
    } else {
        Err(NatServiceError::NotFound(key))?
    }
}

#[utoipa::path(
    put,
    path = "/nat",
    tag = "NAT Service",
    request_body = NatServiceConfig,
    responses((status = 200, description = "Success"))
)]
async fn handle_iface_nat_status(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<NatServiceConfig>,
) -> LandscapeApiResult<()> {
    state.validate_zone(&config).await?;
    config.nat_config.validate()?;
    state.static_nat4_mapping_service.check_dynamic_range_overlap(&config.nat_config).await?;
    state.nat_service.handle_service_config(config).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/nat/{iface_name}",
    tag = "NAT Service",
    params(("iface_name" = String, Path, description = "Interface name")),
    responses((status = 200, description = "Success", body = CommonApiResp<Option<ServiceStatus>>))
)]
async fn delete_and_stop_iface_nat(
    State(state): State<LandscapeApp>,
    Path(iface_name): Path<String>,
) -> LandscapeApiResult<Option<ServiceStatus>> {
    LandscapeApiResp::success(state.nat_service.delete_and_stop_iface_service(iface_name).await?)
}
