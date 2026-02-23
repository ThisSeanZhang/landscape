use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::config::{nat::StaticNatMappingConfig, ConfigId};
use landscape_common::service::controller_service_v2::ConfigController;

use landscape_common::config::nat::StaticNatError;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub async fn get_static_nat_mapping_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/static_nat_mappings", get(get_static_nat_mappings).post(add_static_nat_mappings))
        .route("/static_nat_mappings/set_many", post(add_many_static_nat_mappings))
        .route(
            "/static_nat_mappings/{id}",
            get(get_static_nat_mapping).delete(del_static_nat_mappings),
        )
}

async fn get_static_nat_mappings(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<StaticNatMappingConfig>> {
    let result = state.static_nat_mapping_config_service.list().await;
    LandscapeApiResp::success(result)
}

async fn get_static_nat_mapping(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<StaticNatMappingConfig> {
    let result = state.static_nat_mapping_config_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(StaticNatError::NotFound(id))?
    }
}

async fn add_many_static_nat_mappings(
    State(state): State<LandscapeApp>,
    Json(static_nat_mappings): Json<Vec<StaticNatMappingConfig>>,
) -> LandscapeApiResult<()> {
    state.static_nat_mapping_config_service.set_list(static_nat_mappings).await;
    LandscapeApiResp::success(())
}

async fn add_static_nat_mappings(
    State(state): State<LandscapeApp>,
    Json(static_nat_mapping): Json<StaticNatMappingConfig>,
) -> LandscapeApiResult<StaticNatMappingConfig> {
    let result = state.static_nat_mapping_config_service.set(static_nat_mapping).await;
    LandscapeApiResp::success(result)
}

async fn del_static_nat_mappings(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.static_nat_mapping_config_service.delete(id).await;
    LandscapeApiResp::success(())
}
