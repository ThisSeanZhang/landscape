use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::route::trace::{
    FlowMatchRequest, FlowMatchResult, FlowVerdictRequest, FlowVerdictResult,
};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::JsonBody;
use crate::LandscapeApp;
use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

pub fn get_route_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(reset_cache))
        .routes(routes!(trace_flow_match))
        .routes(routes!(trace_verdict))
}

#[utoipa::path(
    post,
    path = "/routing/reset_cache",
    tag = "Route",
    responses((status = 200, description = "Success"))
)]
async fn reset_cache() -> LandscapeApiResult<()> {
    landscape_ebpf::map_setting::route::cache::recreate_route_lan_cache_inner_map();
    // landscape_ebpf::map_setting::route::cache::recreate_route_wan_cache_inner_map();
    LandscapeApiResp::success(())
}

#[utoipa::path(
    post,
    path = "/routing/trace/flow_match",
    tag = "Route",
    request_body = FlowMatchRequest,
    responses((status = 200, body = inline(CommonApiResp<FlowMatchResult>)))
)]
async fn trace_flow_match(
    JsonBody(req): JsonBody<FlowMatchRequest>,
) -> LandscapeApiResult<FlowMatchResult> {
    let result = landscape_ebpf::map_setting::route::trace_flow_match(req);
    LandscapeApiResp::success(result)
}

#[utoipa::path(
    post,
    path = "/routing/trace/verdict",
    tag = "Route",
    request_body = FlowVerdictRequest,
    responses((status = 200, body = inline(CommonApiResp<FlowVerdictResult>)))
)]
async fn trace_verdict(
    JsonBody(req): JsonBody<FlowVerdictRequest>,
) -> LandscapeApiResult<FlowVerdictResult> {
    let result = landscape_ebpf::map_setting::route::trace_flow_verdict(req);
    LandscapeApiResp::success(result)
}
