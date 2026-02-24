use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{
    geo::{
        GeoFileCacheKey, GeoIpConfig, GeoIpError, GeoIpSourceConfig, QueryGeoIpConfig, QueryGeoKey,
    },
    ConfigId,
};
use landscape_common::service::controller_service_v2::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::{JsonBody, UploadFileForm};
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, UPLOAD_GEO_FILE_SIZE_LIMIT};

pub fn get_geo_ip_config_paths() -> OpenApiRouter<LandscapeApp> {
    let upload_router = OpenApiRouter::new()
        .routes(routes!(update_by_upload))
        .layer(DefaultBodyLimit::max(UPLOAD_GEO_FILE_SIZE_LIMIT));

    OpenApiRouter::new()
        .routes(routes!(get_geo_ips, add_geo_ip))
        .routes(routes!(add_many_geo_ips))
        .routes(routes!(get_geo_ip_rule, del_geo_ip))
        .routes(routes!(get_geo_ip_cache, refresh_geo_ip_cache))
        .routes(routes!(search_geo_ip_cache))
        .routes(routes!(get_geo_ip_cache_detail))
        .merge(upload_router)
}

#[utoipa::path(
    get,
    path = "/ips/cache/detail",
    tag = "Geo IPs",
    params(
        ("name" = String, Query, description = "Geo file name"),
        ("key" = String, Query, description = "Geo cache key")
    ),
    responses(
        (status = 200, body = inline(CommonApiResp<GeoIpConfig>)),
        (status = 404, description = "Not found")
    )
)]
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

#[utoipa::path(
    get,
    path = "/ips/cache/search",
    tag = "Geo IPs",
    params(
        ("name" = Option<String>, Query, description = "Filter by name"),
        ("key" = Option<String>, Query, description = "Filter by key")
    ),
    responses((status = 200, body = inline(CommonApiResp<Vec<GeoFileCacheKey>>)))
)]
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

#[utoipa::path(
    get,
    path = "/ips/cache",
    tag = "Geo IPs",
    responses((status = 200, body = inline(CommonApiResp<Vec<GeoFileCacheKey>>)))
)]
async fn get_geo_ip_cache(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<GeoFileCacheKey>> {
    let result = state.geo_ip_service.list_all_keys().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/ips/cache",
    tag = "Geo IPs",
    responses((status = 200, description = "Success"))
)]
async fn refresh_geo_ip_cache(State(state): State<LandscapeApp>) -> LandscapeApiResult<()> {
    state.geo_ip_service.refresh(true).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/ips",
    tag = "Geo IPs",
    params(
        ("name" = Option<String>, Query, description = "Filter by name")
    ),
    responses((status = 200, body = inline(CommonApiResp<Vec<GeoIpSourceConfig>>)))
)]
async fn get_geo_ips(
    State(state): State<LandscapeApp>,
    Query(q): Query<QueryGeoIpConfig>,
) -> LandscapeApiResult<Vec<GeoIpSourceConfig>> {
    let result = state.geo_ip_service.query_geo_by_name(q.name).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/ips/{id}",
    tag = "Geo IPs",
    params(("id" = Uuid, Path, description = "Geo IP rule ID")),
    responses(
        (status = 200, body = inline(CommonApiResp<GeoIpSourceConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_geo_ip_rule(
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

#[utoipa::path(
    post,
    path = "/ips",
    tag = "Geo IPs",
    request_body = GeoIpSourceConfig,
    responses((status = 200, body = inline(CommonApiResp<GeoIpSourceConfig>)))
)]
async fn add_geo_ip(
    State(state): State<LandscapeApp>,
    JsonBody(dns_rule): JsonBody<GeoIpSourceConfig>,
) -> LandscapeApiResult<GeoIpSourceConfig> {
    let result = state.geo_ip_service.set(dns_rule).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/ips/batch",
    tag = "Geo IPs",
    request_body = Vec<GeoIpSourceConfig>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_geo_ips(
    State(state): State<LandscapeApp>,
    JsonBody(rules): JsonBody<Vec<GeoIpSourceConfig>>,
) -> LandscapeApiResult<()> {
    state.geo_ip_service.set_list(rules).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/ips/{id}",
    tag = "Geo IPs",
    params(("id" = Uuid, Path, description = "Geo IP rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_geo_ip(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.geo_ip_service.delete(id).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/ips/{name}/update_by_upload",
    tag = "Geo IPs",
    operation_id = "update_geo_ip_by_upload",
    params(("name" = String, Path, description = "Geo IP config name")),
    request_body(content = inline(UploadFileForm), content_type = "multipart/form-data"),
    responses((status = 200, description = "Success"))
)]
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
