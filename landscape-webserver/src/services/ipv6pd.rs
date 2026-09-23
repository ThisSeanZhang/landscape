use std::collections::HashMap;

use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::service::WatchService;
use landscape_common::wan_service::ipv6_pd::IPV6PDPrefixStatus;
use landscape_common::wan_service::ipv6_pd::LDIAPrefix;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;
use uuid::Uuid;

use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

/// PD is now driven by the WAN link runtime; only the read-only prefix views
/// remain here. Per-iface PD config is the `pd` section of a WAN link.
pub fn get_iface_pdclient_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_all_status))
        .routes(routes!(get_current_ip_prefix_info))
        .routes(routes!(get_all_prefix_status))
}

#[utoipa::path(
    get,
    path = "/ipv6pd/prefix-status",
    tag = "IPv6 PD",
    operation_id = "get_all_ipv6pd_prefix_status",
    responses((status = 200, body = CommonApiResp<HashMap<Uuid, IPV6PDPrefixStatus>>))
)]
async fn get_all_prefix_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<Uuid, IPV6PDPrefixStatus>> {
    LandscapeApiResp::success(state.wan_link_service.get_ipv6_prefix_statuses())
}

#[utoipa::path(
    get,
    path = "/ipv6pd/infos",
    tag = "IPv6 PD",
    responses((status = 200, body = CommonApiResp<HashMap<Uuid, Option<LDIAPrefix>>>))
)]
async fn get_current_ip_prefix_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<Uuid, Option<LDIAPrefix>>> {
    LandscapeApiResp::success(state.wan_link_service.get_ipv6_prefix_infos())
}

#[utoipa::path(
    get,
    path = "/ipv6pd/status",
    tag = "IPv6 PD",
    operation_id = "get_all_ipv6pd_status",
    responses((status = 200, body = CommonApiResp<HashMap<String, landscape_common::service::ServiceStatus>>))
)]
async fn get_all_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<HashMap<String, WatchService>> {
    LandscapeApiResp::success(state.wan_link_service.get_all_status().await)
}
