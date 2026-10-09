use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::config_service::static_nat::config6::{
    CreateStaticNatMappingV6Config, StaticNatMappingV6Config, StaticNatMappingV6ConfigView,
    UpdateStaticNatMappingV6Config,
};
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::service::controller::ConfigStoreController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_static_nat_mapping_v6_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_static_nat_mappings_v6, add_static_nat_mapping_v6))
        .routes(routes!(
            get_static_nat_mapping_v6,
            update_static_nat_mapping_v6,
            del_static_nat_mapping_v6
        ))
        .routes(routes!(add_many_static_nat_mappings_v6))
}

#[utoipa::path(
    get,
    path = "/static_mappings/v6",
    tag = "Static NAT Mappings",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<StaticNatMappingV6ConfigView>>))
)]
async fn get_static_nat_mappings_v6(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<StaticNatMappingV6ConfigView>> {
    let result: Vec<StaticNatMappingV6ConfigView> =
        state.static_nat6_mapping_service.list().await?.into_iter().map(Into::into).collect();
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/static_mappings/v6/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v6 ID")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<StaticNatMappingV6ConfigView>),
        (status = 404, description = "Not found")
    )
)]
async fn get_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<StaticNatMappingV6ConfigView> {
    let result = state.static_nat6_mapping_service.find_by_id(id).await?;
    if let Some(config) = result {
        LandscapeApiResp::success(config.into())
    } else {
        Err(StaticNatError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/static_mappings/v6",
    tag = "Static NAT Mappings",
    request_body = CreateStaticNatMappingV6Config,
    responses((status = 200, description = "Success", body = CommonApiResp<StaticNatMappingV6ConfigView>))
)]
async fn add_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<CreateStaticNatMappingV6Config>,
) -> LandscapeApiResult<StaticNatMappingV6ConfigView> {
    let config: StaticNatMappingV6Config = config.into();
    let result = state.static_nat6_mapping_service.checked_set(config).await?;
    LandscapeApiResp::success(result.into())
}

#[utoipa::path(
    put,
    path = "/static_mappings/v6/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v6 ID")),
    request_body = UpdateStaticNatMappingV6Config,
    responses(
        (status = 200, description = "Success", body = CommonApiResp<StaticNatMappingV6ConfigView>),
        (status = 404, description = "Not found")
    )
)]
async fn update_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
    JsonBody(body): JsonBody<UpdateStaticNatMappingV6Config>,
) -> LandscapeApiResult<StaticNatMappingV6ConfigView> {
    if state.static_nat6_mapping_service.find_by_id(id).await?.is_none() {
        Err(StaticNatError::NotFound(id))?;
    }
    // Path id wins; update_at must echo the client's last-seen version.
    let mut config: StaticNatMappingV6Config = body.into();
    config.id = id;
    let result = state.static_nat6_mapping_service.checked_set(config).await?;
    LandscapeApiResp::success(result.into())
}

#[utoipa::path(
    post,
    path = "/static_mappings/v6/batch",
    tag = "Static NAT Mappings",
    request_body = Vec<CreateStaticNatMappingV6Config>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_static_nat_mappings_v6(
    State(state): State<LandscapeApp>,
    JsonBody(configs): JsonBody<Vec<CreateStaticNatMappingV6Config>>,
) -> LandscapeApiResult<()> {
    let configs: Vec<StaticNatMappingV6Config> = configs.into_iter().map(Into::into).collect();
    state.static_nat6_mapping_service.checked_set_list(configs).await?;
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
    state.static_nat6_mapping_service.delete(id).await?;
    LandscapeApiResp::success(())
}
