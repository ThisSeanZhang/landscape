use axum::extract::{Query, State};
use landscape_common::api_response::LandscapeApiResp as CommonApiResp;
use landscape_common::metric::connect::{
    ConnectAggregatePoint, ConnectAggregateQueryParams, ConnectGlobalStats,
    ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectMetricPoint, ConnectRealtimeStatus,
    GetConnectGlobalStatsParams, IfaceRealtimeStat, IpHistoryStat, IpRealtimeStat,
    MetricChartRequest,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_common::service::ServiceStatus;
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
        .routes(routes!(get_connect_aggregates))
        .routes(routes!(get_iface_stats))
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
    path = "/connections/iface_stats",
    tag = "Metric",
    operation_id = "get_iface_stats",
    responses((status = 200, body = CommonApiResp<Vec<IfaceRealtimeStat>>))
)]
async fn get_iface_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IfaceRealtimeStat>> {
    let data = state.metric_service.get_realtime_iface_stats().await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/status",
    tag = "Metric",
    operation_id = "get_metric_status",
    responses((status = 200, body = CommonApiResp<ServiceStatus>))
)]
async fn get_metric_status(State(state): State<LandscapeApp>) -> LandscapeApiResult<ServiceStatus> {
    let status = state.metric_service.status.0.borrow().clone();
    LandscapeApiResp::success(status)
}

#[utoipa::path(
    get,
    path = "/connections",
    tag = "Metric",
    operation_id = "get_connects_info",
    responses((status = 200, body = CommonApiResp<Vec<ConnectRealtimeStatus>>))
)]
async fn get_connects_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<ConnectRealtimeStatus>> {
    let data = state.metric_service.connect_infos().await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    post,
    path = "/connections/chart",
    tag = "Metric",
    operation_id = "get_connect_metric_info",
    request_body = MetricChartRequest,
    responses((status = 200, body = CommonApiResp<Vec<ConnectMetricPoint>>))
)]
async fn get_connect_metric_info(
    State(state): State<LandscapeApp>,
    JsonBody(req): JsonBody<MetricChartRequest>,
) -> LandscapeApiResult<Vec<ConnectMetricPoint>> {
    let resolution = req.resolution.unwrap_or_default();
    let data = state.metric_service.query_metric_by_key(req.key, resolution).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connections/history",
    tag = "Metric",
    operation_id = "get_connect_history",
    params(ConnectHistoryQueryParams),
    responses((status = 200, body = CommonApiResp<Vec<ConnectHistoryStatus>>))
)]
async fn get_connect_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<ConnectHistoryStatus>> {
    let data = state.metric_service.history_summaries_complex(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connections/global_stats",
    tag = "Metric",
    operation_id = "get_connect_global_stats",
    params(GetConnectGlobalStatsParams),
    responses((status = 200, body = CommonApiResp<ConnectGlobalStats>))
)]
async fn get_connect_global_stats(
    State(state): State<LandscapeApp>,
    Query(params): Query<GetConnectGlobalStatsParams>,
) -> LandscapeApiResult<ConnectGlobalStats> {
    let data = state.metric_service.get_global_stats(params.force_refresh.unwrap_or(false)).await?;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connections/aggregates",
    tag = "Metric",
    operation_id = "get_connect_aggregates",
    params(ConnectAggregateQueryParams),
    responses((status = 200, body = CommonApiResp<Vec<ConnectAggregatePoint>>))
)]
async fn get_connect_aggregates(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectAggregateQueryParams>,
) -> LandscapeApiResult<Vec<ConnectAggregatePoint>> {
    let data = state.metric_service.query_connection_aggregates(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connections/src_ip_stats",
    tag = "Metric",
    operation_id = "get_src_ip_stats",
    responses((status = 200, body = CommonApiResp<Vec<IpRealtimeStat>>))
)]
async fn get_src_ip_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpRealtimeStat>> {
    let data = state.metric_service.get_realtime_ip_stats(true).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connections/dst_ip_stats",
    tag = "Metric",
    operation_id = "get_dst_ip_stats",
    responses((status = 200, body = CommonApiResp<Vec<IpRealtimeStat>>))
)]
async fn get_dst_ip_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpRealtimeStat>> {
    let data = state.metric_service.get_realtime_ip_stats(false).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connections/history/src_ip_stats",
    tag = "Metric",
    operation_id = "get_history_src_ip_stats",
    params(ConnectHistoryQueryParams),
    responses((status = 200, body = CommonApiResp<Vec<IpHistoryStat>>))
)]
async fn get_history_src_ip_stats(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<IpHistoryStat>> {
    let data = state.metric_service.history_src_ip_stats(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/connections/history/dst_ip_stats",
    tag = "Metric",
    operation_id = "get_history_dst_ip_stats",
    params(ConnectHistoryQueryParams),
    responses((status = 200, body = CommonApiResp<Vec<IpHistoryStat>>))
)]
async fn get_history_dst_ip_stats(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<IpHistoryStat>> {
    let data = state.metric_service.history_dst_ip_stats(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/dns/history",
    tag = "Metric",
    operation_id = "get_dns_history",
    params(DnsHistoryQueryParams),
    responses((status = 200, body = CommonApiResp<DnsHistoryResponse>))
)]
async fn get_dns_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsHistoryQueryParams>,
) -> LandscapeApiResult<DnsHistoryResponse> {
    let data = state.metric_service.query_dns_history(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/dns/summary",
    tag = "Metric",
    operation_id = "get_dns_summary",
    params(DnsSummaryQueryParams),
    responses((status = 200, body = CommonApiResp<DnsSummaryResponse>))
)]
async fn get_dns_summary(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsSummaryQueryParams>,
) -> LandscapeApiResult<DnsSummaryResponse> {
    let data = state.metric_service.get_dns_summary(params).await;
    LandscapeApiResp::success(data)
}

#[utoipa::path(
    get,
    path = "/dns/summary/lightweight",
    tag = "Metric",
    operation_id = "get_dns_lightweight_summary",
    params(DnsSummaryQueryParams),
    responses((status = 200, body = CommonApiResp<DnsLightweightSummaryResponse>))
)]
async fn get_dns_lightweight_summary(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsSummaryQueryParams>,
) -> LandscapeApiResult<DnsLightweightSummaryResponse> {
    let data = state.metric_service.get_dns_lightweight_summary(params).await;
    LandscapeApiResp::success(data)
}
