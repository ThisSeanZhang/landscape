use axum::extract::{Path, Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::config_service::static_nat::config::PortConflictCheckResponse;
use landscape_common::config_service::static_nat::config4::{
    CreateStaticNatMappingV4Config, StaticNatMappingV4Config, StaticNatMappingV4ConfigView,
    UpdateStaticNatMappingV4Config,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::service::controller::ConfigStoreController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_static_nat_mapping_v4_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_static_nat_mappings_v4, add_static_nat_mapping_v4))
        .routes(routes!(
            get_static_nat_mapping_v4,
            update_static_nat_mapping_v4,
            del_static_nat_mapping_v4
        ))
        .routes(routes!(add_many_static_nat_mappings_v4))
        .routes(routes!(check_static_nat_v4_conflict))
}

#[utoipa::path(
    get,
    path = "/static_mappings/v4",
    tag = "Static NAT Mappings",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<StaticNatMappingV4ConfigView>>))
)]
async fn get_static_nat_mappings_v4(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<StaticNatMappingV4ConfigView>> {
    let result: Vec<StaticNatMappingV4ConfigView> =
        state.static_nat4_mapping_service.list().await?.into_iter().map(Into::into).collect();
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/static_mappings/v4/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v4 ID")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<StaticNatMappingV4ConfigView>),
        (status = 404, description = "Not found")
    )
)]
async fn get_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<StaticNatMappingV4ConfigView> {
    let result = state.static_nat4_mapping_service.find_by_id(id).await?;
    if let Some(config) = result {
        LandscapeApiResp::success(config.into())
    } else {
        Err(StaticNatError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/static_mappings/v4",
    tag = "Static NAT Mappings",
    request_body = CreateStaticNatMappingV4Config,
    responses((status = 200, description = "Success", body = CommonApiResp<StaticNatMappingV4ConfigView>))
)]
async fn add_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<CreateStaticNatMappingV4Config>,
) -> LandscapeApiResult<StaticNatMappingV4ConfigView> {
    let config: StaticNatMappingV4Config = config.into();
    let result = state.static_nat4_mapping_service.checked_set(config).await?;
    LandscapeApiResp::success(result.into())
}

#[utoipa::path(
    put,
    path = "/static_mappings/v4/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v4 ID")),
    request_body = UpdateStaticNatMappingV4Config,
    responses(
        (status = 200, description = "Success", body = CommonApiResp<StaticNatMappingV4ConfigView>),
        (status = 404, description = "Not found")
    )
)]
async fn update_static_nat_mapping_v4(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(body): JsonBody<UpdateStaticNatMappingV4Config>,
) -> LandscapeApiResult<StaticNatMappingV4ConfigView> {
    if state.static_nat4_mapping_service.find_by_id(id).await?.is_none() {
        Err(StaticNatError::NotFound(id))?;
    }
    // Path id wins; update_at must echo the client's last-seen version.
    let mut config: StaticNatMappingV4Config = body.into();
    config.id = id;
    let result = state.static_nat4_mapping_service.checked_set(config).await?;
    LandscapeApiResp::success(result.into())
}

#[utoipa::path(
    post,
    path = "/static_mappings/v4/batch",
    tag = "Static NAT Mappings",
    request_body = Vec<CreateStaticNatMappingV4Config>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_static_nat_mappings_v4(
    State(state): State<LandscapeApp>,
    JsonBody(configs): JsonBody<Vec<CreateStaticNatMappingV4Config>>,
) -> LandscapeApiResult<()> {
    let configs: Vec<StaticNatMappingV4Config> = configs.into_iter().map(Into::into).collect();
    state.static_nat4_mapping_service.checked_set_list(configs).await?;
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
    state.static_nat4_mapping_service.delete(id).await?;
    LandscapeApiResp::success(())
}

#[derive(serde::Deserialize)]
struct CheckConflictQuery {
    wan_port: u16,
    protocols: String,
}

#[utoipa::path(
    get,
    path = "/static_mappings/v4/check-conflict",
    tag = "Static NAT Mappings",
    params(
        ("wan_port" = u16, Query, description = "WAN port to check for dynamic range conflict"),
        ("protocols" = String, Query, description = "Comma-separated protocol numbers (6=TCP, 17=UDP)")
    ),
    responses((status = 200, description = "Success", body = CommonApiResp<PortConflictCheckResponse>))
)]
async fn check_static_nat_v4_conflict(
    State(state): State<LandscapeApp>,
    Query(params): Query<CheckConflictQuery>,
) -> LandscapeApiResult<PortConflictCheckResponse> {
    let protocols: Vec<u8> =
        params.protocols.split(',').filter_map(|s| s.trim().parse().ok()).collect();

    match state.static_nat4_mapping_service.check_port_conflict(params.wan_port, &protocols).await?
    {
        Some(StaticNatError::PortConflict { port, iface_name, protocol, start, end }) => {
            LandscapeApiResp::success(PortConflictCheckResponse {
                conflict: true,
                port: Some(port),
                protocol: Some(protocol),
                iface_name: Some(iface_name),
                start: Some(start),
                end: Some(end),
            })
        }
        _ => LandscapeApiResp::success(PortConflictCheckResponse {
            conflict: false,
            port: None,
            protocol: None,
            iface_name: None,
            start: None,
            end: None,
        }),
    }
}
