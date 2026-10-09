use axum::extract::State;
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::flow::trace::{
    FlowMatchRequest, FlowMatchResult, FlowVerdictRequest, FlowVerdictResult,
};
use landscape_common::sys_service::route_service::{
    Ipv4LanRouteEntry, Ipv6LanRouteEntry, RouteStatusView, WanRouteEntry,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::LandscapeApp;
use crate::api::JsonBody;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_route_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(reset_cache))
        .routes(routes!(trace_flow_match))
        .routes(routes!(trace_verdict))
        .routes(routes!(get_routing_status))
}

#[utoipa::path(
    post,
    path = "/routing/reset_cache",
    tag = "Route",
    responses((status = 200, description = "Success"))
)]
async fn reset_cache(State(state): State<LandscapeApp>) -> LandscapeApiResult<()> {
    landscape_ebpf::maps::route::cache::recreate_route_lan_cache_inner_map(&state.ebpf_paths);
    // landscape_ebpf::maps::route::cache::recreate_route_wan_cache_inner_map();
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/routing/trace/flow_match",
    tag = "Route",
    request_body = FlowMatchRequest,
    responses((status = 200, description = "Success", body = CommonApiResp<FlowMatchResult>))
)]
async fn trace_flow_match(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<FlowMatchRequest>,
) -> LandscapeApiResult<FlowMatchResult> {
    let result = landscape_ebpf::maps::route::trace_flow_match(&state.ebpf_paths, req);
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/routing/trace/verdict",
    tag = "Route",
    request_body = FlowVerdictRequest,
    responses((status = 200, description = "Success", body = CommonApiResp<FlowVerdictResult>))
)]
async fn trace_verdict(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<FlowVerdictRequest>,
) -> LandscapeApiResult<FlowVerdictResult> {
    let result = landscape_ebpf::maps::route::trace_flow_verdict(&state.ebpf_paths, req);
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    get,
    path = "/routing/status",
    tag = "Route",
    responses((status = 200, description = "Success", body = CommonApiResp<RouteStatusView>))
)]
async fn get_routing_status(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<RouteStatusView> {
    let ipv4_wan = state.route_service.get_all_ipv4_wan_routes().await;
    let ipv6_wan = state.route_service.get_all_ipv6_wan_routes().await;
    let ipv4_lan = state.route_service.get_all_ipv4_lan_routes().await;
    let ipv6_lan = state.route_service.get_all_ipv6_lan_routes().await;

    let mut ipv4_wan: Vec<WanRouteEntry> =
        ipv4_wan.into_iter().map(|(owner, info)| WanRouteEntry { owner, info }).collect();
    let mut ipv6_wan: Vec<WanRouteEntry> =
        ipv6_wan.into_iter().map(|(owner, info)| WanRouteEntry { owner, info }).collect();
    ipv4_wan.sort_by_key(|entry| entry.info.iface_name.clone());
    ipv6_wan.sort_by_key(|entry| entry.info.iface_name.clone());

    let mut ipv4_lan: Vec<Ipv4LanRouteEntry> = ipv4_lan
        .into_iter()
        .flat_map(|(owner, infos)| {
            infos.into_iter().map(move |info| Ipv4LanRouteEntry { owner: owner.clone(), info })
        })
        .collect();
    ipv4_lan.sort_by(|a, b| a.owner.cmp(&b.owner).then(a.info.iface_ip.cmp(&b.info.iface_ip)));

    let mut ipv6_lan: Vec<Ipv6LanRouteEntry> =
        ipv6_lan.into_iter().map(|(key, info)| Ipv6LanRouteEntry { key, info }).collect();
    ipv6_lan.sort_by(|a, b| {
        a.key
            .iface_name
            .cmp(&b.key.iface_name)
            .then(a.key.subnet.cmp(&b.key.subnet))
            .then(a.key.prefix_len.cmp(&b.key.prefix_len))
    });

    LandscapeApiResp::success(RouteStatusView { ipv4_wan, ipv6_wan, ipv4_lan, ipv6_lan })
}
