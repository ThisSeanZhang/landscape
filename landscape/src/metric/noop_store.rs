use std::path::PathBuf;

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey, ConnectMetric,
    ConnectMetricPoint, ConnectRealtimeStatus, IpRealtimeStat, MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSummaryQueryParams, DnsSummaryResponse,
};

/// A no-op metric store that returns empty results.
/// Used when the `metric-duckdb` feature is disabled to avoid compiling DuckDB.
#[derive(Clone)]
pub struct NoopMetricStore;

impl NoopMetricStore {
    pub async fn new(_base_path: PathBuf, _config: MetricRuntimeConfig) -> Self {
        tracing::info!(
            "Metric store disabled (metric-duckdb feature not enabled), using no-op store"
        );
        NoopMetricStore
    }

    pub async fn insert_metric(&self, _metric: ConnectMetric) {}

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        Vec::new()
    }

    pub async fn get_realtime_ip_stats(&self, _is_src: bool) -> Vec<IpRealtimeStat> {
        Vec::new()
    }

    pub async fn query_metric_by_key(
        &self,
        _key: ConnectKey,
        _resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        Vec::new()
    }

    pub async fn collect_and_cleanup_old_metrics(
        &self,
        _cutoff_raw: u64,
        _cutoff_1m: u64,
        _cutoff_1h: u64,
        _cutoff_1d: u64,
    ) -> Box<Vec<ConnectMetric>> {
        Box::new(Vec::new())
    }

    pub async fn history_summaries_complex(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        Vec::new()
    }

    pub async fn history_src_ip_stats(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<landscape_common::metric::connect::IpHistoryStat> {
        Vec::new()
    }

    pub async fn history_dst_ip_stats(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<landscape_common::metric::connect::IpHistoryStat> {
        Vec::new()
    }

    pub async fn get_global_stats(&self) -> ConnectGlobalStats {
        ConnectGlobalStats::default()
    }

    pub async fn insert_dns_metric(&self, _metric: DnsMetric) {}

    pub async fn query_dns_history(&self, _params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        DnsHistoryResponse { items: Vec::new(), total: 0 }
    }

    pub async fn get_dns_summary(&self, _params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        DnsSummaryResponse::default()
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        _params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        DnsLightweightSummaryResponse::default()
    }
}
