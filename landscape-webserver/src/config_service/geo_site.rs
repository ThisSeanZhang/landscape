use axum::{
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    routing::post,
};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::{
    geo::{
        GeoDomainConfig, GeoFileCacheKey, GeoSiteError, GeoSiteSourceConfig, QueryGeoDomainConfig,
        QueryGeoKey,
    },
    ConfigId,
};
use landscape_common::service::controller_service_v2::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult, UPLOAD_GEO_FILE_SIZE_LIMIT};

pub fn get_geo_site_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_geo_sites, add_geo_site))
        .routes(routes!(add_many_geo_sites))
        .routes(routes!(get_geo_rule, del_geo_site))
        .routes(routes!(get_geo_site_cache, refresh_geo_site_cache))
        .routes(routes!(search_geo_site_cache))
        .routes(routes!(get_geo_site_cache_detail))
}

/// Returns a separate Router for the upload endpoint that cannot use utoipa annotations.
pub fn get_geo_site_upload_path() -> axum::Router<LandscapeApp> {
    axum::Router::new().route(
        "/geo_sites/{name}/update_by_upload",
        post(update_by_upload).layer(DefaultBodyLimit::max(UPLOAD_GEO_FILE_SIZE_LIMIT)),
    )
}

#[utoipa::path(
    get,
    path = "/geo_sites/cache/detail",
    tag = "Geo Sites",
    params(
        ("name" = String, Query, description = "Geo file name"),
        ("key" = String, Query, description = "Geo cache key")
    ),
    responses(
        (status = 200, body = inline(CommonApiResp<GeoDomainConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_geo_site_cache_detail(
    State(state): State<LandscapeApp>,
    Query(key): Query<GeoFileCacheKey>,
) -> LandscapeApiResult<GeoDomainConfig> {
    let result = state.geo_site_service.get_cache_value_by_key(&key).await;
    if let Some(result) = result {
        LandscapeApiResp::success(result)
    } else {
        Err(GeoSiteError::CacheNotFound(format!("{key:?}")))?
    }
}

#[utoipa::path(
    get,
    path = "/geo_sites/cache/search",
    tag = "Geo Sites",
    params(
        ("name" = Option<String>, Query, description = "Filter by name"),
        ("key" = Option<String>, Query, description = "Filter by key")
    ),
    responses((status = 200, body = inline(CommonApiResp<Vec<GeoFileCacheKey>>)))
)]
async fn search_geo_site_cache(
    State(state): State<LandscapeApp>,
    Query(query): Query<QueryGeoKey>,
) -> LandscapeApiResult<Vec<GeoFileCacheKey>> {
    tracing::debug!("query: {:?}", query);
    let key = query.key.map(|k| k.to_ascii_uppercase());
    let name = query.name;
    tracing::debug!("name: {name:?}");
    tracing::debug!("key: {key:?}");
    let result: Vec<GeoFileCacheKey> = state
        .geo_site_service
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
    path = "/geo_sites/cache",
    tag = "Geo Sites",
    responses((status = 200, body = inline(CommonApiResp<Vec<GeoFileCacheKey>>)))
)]
async fn get_geo_site_cache(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<GeoFileCacheKey>> {
    let result = state.geo_site_service.list_all_keys().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/geo_sites/cache",
    tag = "Geo Sites",
    responses((status = 200, description = "Success"))
)]
async fn refresh_geo_site_cache(State(state): State<LandscapeApp>) -> LandscapeApiResult<()> {
    state.geo_site_service.refresh(true).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    get,
    path = "/geo_sites",
    tag = "Geo Sites",
    params(
        ("name" = Option<String>, Query, description = "Filter by name")
    ),
    responses((status = 200, body = inline(CommonApiResp<Vec<GeoSiteSourceConfig>>)))
)]
async fn get_geo_sites(
    State(state): State<LandscapeApp>,
    Query(q): Query<QueryGeoDomainConfig>,
) -> LandscapeApiResult<Vec<GeoSiteSourceConfig>> {
    let result = state.geo_site_service.query_geo_by_name(q.name).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/geo_sites/{id}",
    tag = "Geo Sites",
    params(("id" = Uuid, Path, description = "Geo site rule ID")),
    responses(
        (status = 200, body = inline(CommonApiResp<GeoSiteSourceConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_geo_rule(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<GeoSiteSourceConfig> {
    let result = state.geo_site_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(GeoSiteError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/geo_sites",
    tag = "Geo Sites",
    request_body = GeoSiteSourceConfig,
    responses((status = 200, body = inline(CommonApiResp<GeoSiteSourceConfig>)))
)]
async fn add_geo_site(
    State(state): State<LandscapeApp>,
    JsonBody(dns_rule): JsonBody<GeoSiteSourceConfig>,
) -> LandscapeApiResult<GeoSiteSourceConfig> {
    let result = state.geo_site_service.set(dns_rule).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/geo_sites/set_many",
    tag = "Geo Sites",
    request_body = Vec<GeoSiteSourceConfig>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_geo_sites(
    State(state): State<LandscapeApp>,
    JsonBody(rules): JsonBody<Vec<GeoSiteSourceConfig>>,
) -> LandscapeApiResult<()> {
    state.geo_site_service.set_list(rules).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    delete,
    path = "/geo_sites/{id}",
    tag = "Geo Sites",
    params(("id" = Uuid, Path, description = "Geo site rule ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_geo_site(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.geo_site_service.delete(id).await;
    LandscapeApiResp::success(())
}

// curl -vvv -k -X POST https://localhost:6443/api/src/config/geo_sites/test2/update_by_upload
// -H "Authorization: Bearer $(cat ../.landscape-router/landscape_api_token)"
//  -F "file=@../.landscape-router/geosite.dat1"
async fn update_by_upload(
    State(state): State<LandscapeApp>,
    Path(name): Path<String>,
    mut multipart: Multipart,
) -> LandscapeApiResult<()> {
    tracing::info!("Got upload request for: {}", name);

    let file = multipart.next_field().await;
    let Ok(Some(field)) = file else {
        return Err(GeoSiteError::FileNotFound)?;
    };

    let Ok(bytes) = field.bytes().await else {
        return Err(GeoSiteError::FileReadError)?;
    };

    state.geo_site_service.update_geo_config_by_bytes(name, bytes).await;

    LandscapeApiResp::success(())
}
