use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::config::{
    geo::{
        GeoFileCacheKey, GeoIpConfig, GeoIpError, GeoIpSourceConfig, QueryGeoIpConfig, QueryGeoKey,
    },
    ConfigId,
};
use landscape_common::service::controller_service_v2::ConfigController;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, UPLOAD_GEO_FILE_SIZE_LIMIT};

pub async fn get_geo_ip_config_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/geo_ips", get(get_geo_ips).post(add_geo_ip))
        .route("/geo_ips/set_many", post(add_many_geo_ips))
        .route("/geo_ips/{id}", get(get_geo_rule).delete(del_geo_ip))
        .route("/geo_ips/cache", get(get_geo_ip_cache).post(refresh_geo_ip_cache))
        .route("/geo_ips/cache/search", get(search_geo_ip_cache))
        .route("/geo_ips/cache/detail", get(get_geo_ip_cache_detail))
        .route(
            "/geo_ips/{name}/update_by_upload",
            post(update_by_upload).layer(DefaultBodyLimit::max(UPLOAD_GEO_FILE_SIZE_LIMIT)),
        )
}

async fn get_geo_ip_cache_detail(
    State(state): State<LandscapeApp>,
    Query(key): Query<GeoFileCacheKey>,
) -> LandscapeApiResult<GeoIpConfig> {
    let result = state.geo_ip_service.get_cache_value_by_key(&key).await;
    if let Some(result) = result {
        LandscapeApiResp::success(result)
    } else {
        Err(GeoIpError::CacheNotFound(format!("{key:?}")))?
    }
}

async fn search_geo_ip_cache(
    State(state): State<LandscapeApp>,
    Query(query): Query<QueryGeoKey>,
) -> LandscapeApiResult<Vec<GeoFileCacheKey>> {
    tracing::debug!("query: {:?}", query);
    let key = query.key.map(|k| k.to_ascii_uppercase());
    let name = query.name;
    tracing::debug!("name: {name:?}");
    tracing::debug!("key: {key:?}");
    let result: Vec<GeoFileCacheKey> = state
        .geo_ip_service
        .list_all_keys()
        .await
        .into_iter()
        .filter(|e| key.as_ref().map_or(true, |key| e.key.contains(key)))
        .filter(|e| name.as_ref().map_or(true, |name| &e.name == name))
        .collect();

    tracing::debug!("keys len: {}", result.len());
    LandscapeApiResp::success(result)
}

async fn get_geo_ip_cache(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<GeoFileCacheKey>> {
    let result = state.geo_ip_service.list_all_keys().await;
    LandscapeApiResp::success(result)
}

async fn refresh_geo_ip_cache(State(state): State<LandscapeApp>) -> LandscapeApiResult<()> {
    state.geo_ip_service.refresh(true).await;
    LandscapeApiResp::success(())
}

async fn get_geo_ips(
    State(state): State<LandscapeApp>,
    Query(q): Query<QueryGeoIpConfig>,
) -> LandscapeApiResult<Vec<GeoIpSourceConfig>> {
    let result = state.geo_ip_service.query_geo_by_name(q.name).await;
    LandscapeApiResp::success(result)
}

async fn get_geo_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<GeoIpSourceConfig> {
    let result = state.geo_ip_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(GeoIpError::NotFound(id))?
    }
}

async fn add_geo_ip(
    State(state): State<LandscapeApp>,
    Json(dns_rule): Json<GeoIpSourceConfig>,
) -> LandscapeApiResult<GeoIpSourceConfig> {
    let result = state.geo_ip_service.set(dns_rule).await;
    LandscapeApiResp::success(result)
}

async fn add_many_geo_ips(
    State(state): State<LandscapeApp>,
    Json(rules): Json<Vec<GeoIpSourceConfig>>,
) -> LandscapeApiResult<()> {
    state.geo_ip_service.set_list(rules).await;
    LandscapeApiResp::success(())
}

async fn del_geo_ip(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.geo_ip_service.delete(id).await;
    LandscapeApiResp::success(())
}

async fn update_by_upload(
    State(state): State<LandscapeApp>,
    Path(name): Path<String>,
    mut multipart: Multipart,
) -> LandscapeApiResult<()> {
    tracing::info!("Got upload request for: {}", name);

    let file = multipart.next_field().await;
    let Ok(Some(field)) = file else {
        return Err(GeoIpError::FileNotFound)?;
    };

    let Ok(bytes) = field.bytes().await else {
        return Err(GeoIpError::FileReadError)?;
    };

    state.geo_ip_service.update_geo_config_by_bytes(name, bytes).await;

    LandscapeApiResp::success(())
}
