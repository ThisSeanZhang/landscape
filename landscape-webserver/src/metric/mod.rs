use axum::{
    extract::{Query, State},
    routing::{get, post},
    Json, Router,
};
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectMetricPoint,
    ConnectRealtimeStatus, IpRealtimeStat, MetricChartRequest,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use serde_json::Value;

use crate::{api::LandscapeApiResp, error::LandscapeApiResult};

use crate::LandscapeApp;

pub async fn get_metric_service_paths() -> Router<LandscapeApp> {
    Router::new()
        .route("/status", get(get_metric_status))
        .route("/connects", get(get_connects_info))
        .route("/connects/chart", post(get_connect_metric_info))
        .route("/connects/history", get(get_connect_history))
        .route("/connects/global_stats", get(get_connect_global_stats))
        .route("/connects/src_ip_stats", get(get_src_ip_stats))
        .route("/connects/dst_ip_stats", get(get_dst_ip_stats))
        .route("/connects/history/src_ip_stats", get(get_history_src_ip_stats))
        .route("/connects/history/dst_ip_stats", get(get_history_dst_ip_stats))
        .route("/dns/history", get(get_dns_history))
        .route("/dns/summary", get(get_dns_summary))
        .route("/dns/summary/lightweight", get(get_dns_lightweight_summary))
}

pub async fn get_metric_status(State(state): State<LandscapeApp>) -> LandscapeApiResult<Value> {
    LandscapeApiResp::success(serde_json::to_value(&state.metric_service.status).unwrap())
}

pub async fn get_connects_info(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<ConnectRealtimeStatus>> {
    let data = state.metric_service.data.connect_metric.connect_infos().await;
    LandscapeApiResp::success(data)
}

pub async fn get_connect_metric_info(
    State(state): State<LandscapeApp>,
    Json(req): Json<MetricChartRequest>,
) -> LandscapeApiResult<Vec<ConnectMetricPoint>> {
    let data =
        state.metric_service.data.connect_metric.query_metric_by_key(req.key, req.resolution).await;
    LandscapeApiResp::success(data)
}

pub async fn get_connect_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<ConnectHistoryStatus>> {
    let data = state.metric_service.data.connect_metric.history_summaries_complex(params).await;
    LandscapeApiResp::success(data)
}
pub async fn get_connect_global_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<ConnectGlobalStats> {
    let data = state.metric_service.data.connect_metric.get_global_stats().await;
    LandscapeApiResp::success(data)
}
pub async fn get_dns_history(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsHistoryQueryParams>,
) -> LandscapeApiResult<DnsHistoryResponse> {
    let data = state.metric_service.data.dns_metric.query_dns_history(params).await;
    LandscapeApiResp::success(data)
}

pub async fn get_dns_summary(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsSummaryQueryParams>,
) -> LandscapeApiResult<DnsSummaryResponse> {
    let data = state.metric_service.data.dns_metric.get_dns_summary(params).await;
    LandscapeApiResp::success(data)
}

pub async fn get_dns_lightweight_summary(
    State(state): State<LandscapeApp>,
    Query(params): Query<DnsSummaryQueryParams>,
) -> LandscapeApiResult<DnsLightweightSummaryResponse> {
    let data = state.metric_service.data.dns_metric.get_dns_lightweight_summary(params).await;
    LandscapeApiResp::success(data)
}
pub async fn get_src_ip_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpRealtimeStat>> {
    let data = state.metric_service.data.connect_metric.get_src_ip_stats().await;
    LandscapeApiResp::success(data)
}

pub async fn get_dst_ip_stats(
    State(state): State<LandscapeApp>,
) -> LandscapeApiResult<Vec<IpRealtimeStat>> {
    let data = state.metric_service.data.connect_metric.get_dst_ip_stats().await;
    LandscapeApiResp::success(data)
}

pub async fn get_history_src_ip_stats(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<landscape_common::metric::connect::IpHistoryStat>> {
    let data = state.metric_service.data.connect_metric.history_src_ip_stats(params).await;
    LandscapeApiResp::success(data)
}

pub async fn get_history_dst_ip_stats(
    State(state): State<LandscapeApp>,
    Query(params): Query<ConnectHistoryQueryParams>,
) -> LandscapeApiResult<Vec<landscape_common::metric::connect::IpHistoryStat>> {
    let data = state.metric_service.data.connect_metric.history_dst_ip_stats(params).await;
    LandscapeApiResp::success(data)
}
