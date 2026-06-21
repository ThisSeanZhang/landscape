use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::iface::nat::{
    StaticNatError, StaticNatMappingV4Config, StaticNatMappingV6Config,
};
use landscape_common::service::ServiceConfigError;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_static_nat_mapping_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_static_nat_mappings_v4, add_static_nat_mapping_v4))
        .routes(routes!(get_static_nat_mapping_v4, del_static_nat_mapping_v4))
        .routes(routes!(add_many_static_nat_mappings_v4))
        .routes(routes!(get_static_nat_mappings_v6, add_static_nat_mapping_v6))
        .routes(routes!(get_static_nat_mapping_v6, del_static_nat_mapping_v6))
        .routes(routes!(add_many_static_nat_mappings_v6))
}

// ============================================================
// IPv4 endpoints
// ============================================================

#[utoipa::path(
    get,
    path = "/static_mappings/v4",
    tag = "Static NAT Mappings",
    responses((status = 200, body = CommonApiResp<Vec<StaticNatMappingV4Config>>))
)]
async fn get_static_nat_mappings_v4(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<StaticNatMappingV4Config>> {
    let result = state.static_nat_mapping_config_service.list_v4().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/static_mappings/v4/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v4 ID")),
    responses(
        (status = 200, body = CommonApiResp<StaticNatMappingV4Config>),
        (status = 404, description = "Not found")
    )
)]
async fn get_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<StaticNatMappingV4Config> {
    let result = state.static_nat_mapping_config_service.find_v4_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(StaticNatError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/static_mappings/v4",
    tag = "Static NAT Mappings",
    request_body = StaticNatMappingV4Config,
    responses((status = 200, body = CommonApiResp<StaticNatMappingV4Config>))
)]
async fn add_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<StaticNatMappingV4Config>,
) -> LandscapeApiResult<StaticNatMappingV4Config> {
    config.validate()?;
    state
        .static_nat_mapping_config_service
        .validate_runtime_target_v4(&config)
        .await
        .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
    let result = state.static_nat_mapping_config_service.checked_set_v4(config).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/static_mappings/v4/batch",
    tag = "Static NAT Mappings",
    request_body = Vec<StaticNatMappingV4Config>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_static_nat_mappings_v4(
    State(state): State<LandscapeApp>,
    JsonBody(configs): JsonBody<Vec<StaticNatMappingV4Config>>,
) -> LandscapeApiResult<()> {
    for m in &configs {
        m.validate()?;
        state
            .static_nat_mapping_config_service
            .validate_runtime_target_v4(m)
            .await
            .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
    }
    state.static_nat_mapping_config_service.checked_set_list_v4(configs).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/static_mappings/v4/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v4 ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.static_nat_mapping_config_service.delete_v4(id).await;
    LandscapeApiResp::success(())
}

// ============================================================
// IPv6 endpoints
// ============================================================

#[utoipa::path(
    get,
    path = "/static_mappings/v6",
    tag = "Static NAT Mappings",
    responses((status = 200, body = CommonApiResp<Vec<StaticNatMappingV6Config>>))
)]
async fn get_static_nat_mappings_v6(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<StaticNatMappingV6Config>> {
    let result = state.static_nat_mapping_config_service.list_v6().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/static_mappings/v6/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v6 ID")),
    responses(
        (status = 200, body = CommonApiResp<StaticNatMappingV6Config>),
        (status = 404, description = "Not found")
    )
)]
async fn get_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<StaticNatMappingV6Config> {
    let result = state.static_nat_mapping_config_service.find_v6_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(StaticNatError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/static_mappings/v6",
    tag = "Static NAT Mappings",
    request_body = StaticNatMappingV6Config,
    responses((status = 200, body = CommonApiResp<StaticNatMappingV6Config>))
)]
async fn add_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<StaticNatMappingV6Config>,
) -> LandscapeApiResult<StaticNatMappingV6Config> {
    config.validate()?;
    state
        .static_nat_mapping_config_service
        .validate_runtime_target_v6(&config)
        .await
        .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
    let result = state.static_nat_mapping_config_service.checked_set_v6(config).await?;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/static_mappings/v6/batch",
    tag = "Static NAT Mappings",
    request_body = Vec<StaticNatMappingV6Config>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_static_nat_mappings_v6(
    State(state): State<LandscapeApp>,
    JsonBody(configs): JsonBody<Vec<StaticNatMappingV6Config>>,
) -> LandscapeApiResult<()> {
    for m in &configs {
        m.validate()?;
        state
            .static_nat_mapping_config_service
            .validate_runtime_target_v6(m)
            .await
            .map_err(|error| ServiceConfigError::InvalidConfig { reason: error.to_string() })?;
    }
    state.static_nat_mapping_config_service.checked_set_list_v6(configs).await?;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/static_mappings/v6/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v6 ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.static_nat_mapping_config_service.delete_v6(id).await;
    LandscapeApiResp::success(())
}
