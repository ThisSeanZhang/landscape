use axum::extract::{Path, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::config::ConfigId;
use landscape_common::dns::config::DnsUpstreamConfig;
use landscape_common::service::controller_service_v2::ConfigController;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use landscape_common::dns::upstream::DnsUpstreamError;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_dns_upstream_config_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_dns_upstreams, add_dns_upstream))
        .routes(routes!(add_many_dns_upstreams))
        .routes(routes!(get_dns_upstream, del_dns_upstream))
}

#[utoipa::path(
    get,
    path = "/upstreams",
    tag = "DNS Upstreams",
    responses((status = 200, body = inline(CommonApiResp<Vec<DnsUpstreamConfig>>)))
)]
async fn get_dns_upstreams(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<DnsUpstreamConfig>> {
    let result = state.dns_upstream_service.list().await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/upstreams/{id}",
    tag = "DNS Upstreams",
    params(("id" = Uuid, Path, description = "DNS upstream config ID")),
    responses(
        (status = 200, body = inline(CommonApiResp<DnsUpstreamConfig>)),
        (status = 404, description = "Not found")
    )
)]
async fn get_dns_upstream(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<DnsUpstreamConfig> {
    let result = state.dns_upstream_service.find_by_id(id).await;
    if let Some(config) = result {
        LandscapeApiResp::success(config)
    } else {
        Err(DnsUpstreamError::NotFound(id))?
    }
}

#[utoipa::path(
    post,
    path = "/upstreams/batch",
    tag = "DNS Upstreams",
    request_body = Vec<DnsUpstreamConfig>,
    responses((status = 200, description = "Success"))
)]
async fn add_many_dns_upstreams(
    State(state): State<LandscapeApp>,
    JsonBody(dns_upstreams): JsonBody<Vec<DnsUpstreamConfig>>,
) -> LandscapeApiResult<()> {
    state.dns_upstream_service.set_list(dns_upstreams).await;
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/upstreams",
    tag = "DNS Upstreams",
    request_body = DnsUpstreamConfig,
    responses((status = 200, body = inline(CommonApiResp<DnsUpstreamConfig>)))
)]
async fn add_dns_upstream(
    State(state): State<LandscapeApp>,
    JsonBody(dns_upstream): JsonBody<DnsUpstreamConfig>,
) -> LandscapeApiResult<DnsUpstreamConfig> {
    let result = state.dns_upstream_service.set(dns_upstream).await;
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    delete,
    path = "/upstreams/{id}",
    tag = "DNS Upstreams",
    params(("id" = Uuid, Path, description = "DNS upstream config ID")),
    responses(
        (status = 200, description = "Success"),
        (status = 404, description = "Not found")
    )
)]
async fn del_dns_upstream(
    State(state): State<LandscapeApp>,
    Path(id): Path<ConfigId>,
) -> LandscapeApiResult<()> {
    state.dns_upstream_service.delete(id).await;
    LandscapeApiResp::success(())
}
