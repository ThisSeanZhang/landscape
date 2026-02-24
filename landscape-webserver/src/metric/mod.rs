use axum::extract::{Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectMetricPoint,
    ConnectRealtimeStatus, IpHistoryStat, IpRealtimeStat, MetricChartRequest,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use serde_json::Value;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use crate::api::{JsonBody, LandscapeApiResp};
use crate::error::LandscapeApiResult;

use crate::LandscapeApp;

pub fn get_metric_paths() -> OpenApiRouter<LandscapeApp> {
    OpenApiRouter::new()
        .routes(routes!(get_metric_status))
        .routes(routes!(get_connects_info))
        .routes(routes!(get_connect_metric_info))
        .routes(routes!(get_connect_history))
        .routes(routes!(get_connect_global_stats))
        .routes(routes!(get_src_ip_stats))
        .routes(routes!(get_dst_ip_stats))
        .routes(routes!(get_history_src_ip_stats))
        .routes(routes!(get_history_dst_ip_stats))
        .routes(routes!(get_dns_history))
        .routes(routes!(get_dns_summary))
        .routes(routes!(get_dns_lightweight_summary))
}

#[utoipa::path(
    get,
    path = "/status",
    tag = "Metric",
    operation_id = "get_metric_status",
    responses((status = 200, body = inline(CommonApiResp<serde_json::Value>)))
)]
async fn get_metric_status(State(state): State<LandscapeApp>) -> LandscapeApiResult<Value> {
    LandscapeApiResp::success(serde_json::to_value(&state.metric_service.status).unwrap())
}

#[utoipa::path(
    get,
    path = "/connects",
    tag = "Metric",
    operation_id = "get_connects_info",
    responses((status = 200, body = inline(CommonApiResp<Vec<ConnectRealtimeStatus>>)))
)]
async fn get_connects_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<ConnectRealtimeStatus>> {
    let data = state.metric_service.data.connect_metric.connect_infos().await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    post,
    path = "/connects/chart",
    tag = "Metric",
    operation_id = "get_connect_metric_info",
    request_body = MetricChartRequest,
    responses((status = 200, body = inline(CommonApiResp<Vec<ConnectMetricPoint>>)))
)]
async fn get_connect_metric_info(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<MetricChartRequest>,
) -> LandscapeApiResult<Vec<ConnectMetricPoint>> {
    let data =
        state.metric_service.data.connect_metric.query_metric_by_key(req.key, req.resolution).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connects/history",
    tag = "Metric",
    operation_id = "get_connect_history",
    params(ConnectHistoryQueryParams),
    responses((status = 200, body = inline(CommonApiResp<Vec<ConnectHistoryStatus>>)))
)]
async fn get_connect_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<ConnectHistoryStatus>> {
    let data = state.metric_service.data.connect_metric.history_summaries_complex(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connects/global_stats",
    tag = "Metric",
    operation_id = "get_connect_global_stats",
    responses((status = 200, body = inline(CommonApiResp<ConnectGlobalStats>)))
)]
async fn get_connect_global_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<ConnectGlobalStats> {
    let data = state.metric_service.data.connect_metric.get_global_stats().await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connects/src_ip_stats",
    tag = "Metric",
    operation_id = "get_src_ip_stats",
    responses((status = 200, body = inline(CommonApiResp<Vec<IpRealtimeStat>>)))
)]
async fn get_src_ip_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpRealtimeStat>> {
    let data = state.metric_service.data.connect_metric.get_src_ip_stats().await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connects/dst_ip_stats",
    tag = "Metric",
    operation_id = "get_dst_ip_stats",
    responses((status = 200, body = inline(CommonApiResp<Vec<IpRealtimeStat>>)))
)]
async fn get_dst_ip_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpRealtimeStat>> {
    let data = state.metric_service.data.connect_metric.get_dst_ip_stats().await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connects/history/src_ip_stats",
    tag = "Metric",
    operation_id = "get_history_src_ip_stats",
    params(ConnectHistoryQueryParams),
    responses((status = 200, body = inline(CommonApiResp<Vec<IpHistoryStat>>)))
)]
async fn get_history_src_ip_stats(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<IpHistoryStat>> {
    let data = state.metric_service.data.connect_metric.history_src_ip_stats(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connects/history/dst_ip_stats",
    tag = "Metric",
    operation_id = "get_history_dst_ip_stats",
    params(ConnectHistoryQueryParams),
    responses((status = 200, body = inline(CommonApiResp<Vec<IpHistoryStat>>)))
)]
async fn get_history_dst_ip_stats(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<IpHistoryStat>> {
    let data = state.metric_service.data.connect_metric.history_dst_ip_stats(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/dns/history",
    tag = "Metric",
    operation_id = "get_dns_history",
    params(DnsHistoryQueryParams),
    responses((status = 200, body = inline(CommonApiResp<DnsHistoryResponse>)))
)]
async fn get_dns_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsHistoryQueryParams>,
) -> LandscapeApiResult<DnsHistoryResponse> {
    let data = state.metric_service.data.dns_metric.query_dns_history(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/dns/summary",
    tag = "Metric",
    operation_id = "get_dns_summary",
    params(DnsSummaryQueryParams),
    responses((status = 200, body = inline(CommonApiResp<DnsSummaryResponse>)))
)]
async fn get_dns_summary(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsSummaryQueryParams>,
) -> LandscapeApiResult<DnsSummaryResponse> {
    let data = state.metric_service.data.dns_metric.get_dns_summary(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/dns/summary/lightweight",
    tag = "Metric",
    operation_id = "get_dns_lightweight_summary",
    params(DnsSummaryQueryParams),
    responses((status = 200, body = inline(CommonApiResp<DnsLightweightSummaryResponse>)))
)]
async fn get_dns_lightweight_summary(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsSummaryQueryParams>,
) -> LandscapeApiResult<DnsLightweightSummaryResponse> {
    let data = state.metric_service.data.dns_metric.get_dns_lightweight_summary(params).await;
    LandscapeApiResp::success(data)
}
