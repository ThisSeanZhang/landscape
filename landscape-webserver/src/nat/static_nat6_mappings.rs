use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::config_service::static_nat::error::StaticNatError;
use landscape_common::service::controller::ConfigStoreController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

use landscape_common::config_service::static_nat::api::ApiStaticNatMappingV6Config;

pub fn get_static_nat_mapping_v6_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_static_nat_mappings_v6, add_static_nat_mapping_v6))
        .routes(routes!(get_static_nat_mapping_v6, del_static_nat_mapping_v6))
        .routes(routes!(add_many_static_nat_mappings_v6))
}

#[utoipa::path(
    get,
    path = "/static_mappings/v6",
    tag = "Static NAT Mappings",
    responses((status = 200, description = "Success", body = CommonApiResp<Vec<ApiStaticNatMappingV6Config>>))
)]
async fn get_static_nat_mappings_v6(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<ApiStaticNatMappingV6Config>> {
    let result: Vec<ApiStaticNatMappingV6Config> =
        state.static_nat6_mapping_service.list().await?.into_iter().map(Into::into).collect();
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/static_mappings/v6/{id}",
    tag = "Static NAT Mappings",
    params(("id" = Uuid, Path, description = "Static NAT mapping v6 ID")),
    responses(
        (status = 200, description = "Success", body = CommonApiResp<ApiStaticNatMappingV6Config>),
        (status = 404, description = "Not found")
    )
)]
async fn get_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<ApiStaticNatMappingV6Config> {
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
    request_body = ApiStaticNatMappingV6Config,
    responses((status = 200, description = "Success", body = CommonApiResp<ApiStaticNatMappingV6Config>))
)]
async fn add_static_nat_mapping_v6(
    State(state): State<LandscapeApp>,
    JsonBody(config): JsonBody<ApiStaticNatMappingV6Config>,
) -> LandscapeApiResult<ApiStaticNatMappingV6Config> {
    let result = state.static_nat6_mapping_service.checked_set(config.into()).await?;
    LandscapeApiResp::success(result.into())
}

#[utoipa::path(
    post,
    path = "/static_mappings/v6/batch",
    tag = "Static NAT Mappings",
    request_body = Vec<ApiStaticNatMappingV6Config>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_static_nat_mappings_v6(
    State(state): State<LandscapeApp>,
    JsonBody(configs): JsonBody<Vec<ApiStaticNatMappingV6Config>>,
) -> LandscapeApiResult<()> {
    let configs = configs.into_iter().map(Into::into).collect();
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
