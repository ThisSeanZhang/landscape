use landscape_common::config::MetricRuntimeConfig;
use landscape_common::database::error::DbError;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectMetricPoint, IpHistoryStat, MetricResolution,
};
#[cfg(feature = "metric-persistent")]
use landscape_common::metric::dns::DnsMetric;
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};

use crate::agg::Batch;

pub(crate) mod memory;
#[cfg(feature = "metric-persistent")]
pub(crate) mod persistent;

/// 持久化 sink:聚合 worker 产出的批次在此落盘,历史查询在此执行。
/// 内存 sink 的 apply 为 no-op、查询返回空/默认值,两种模式共用同一套聚合层。
#[async_trait::async_trait]
pub(crate) trait MetricSink: Send + Sync {
    async fn apply_connect_batch(&self, batch: &Batch) -> bool;
    #[cfg(feature = "metric-persistent")]
    async fn apply_dns_batch(&self, metrics: Vec<DnsMetric>) -> bool;
    async fn cleanup_connect(&self, config: &MetricRuntimeConfig);
    #[cfg(feature = "metric-persistent")]
    async fn cleanup_dns(&self, config: &MetricRuntimeConfig);
    async fn close(&self);

    async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint>;
    async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus>;
    async fn history_src_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat>;
    async fn history_dst_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat>;
    async fn get_global_stats(&self, force_refresh: bool) -> Result<ConnectGlobalStats, DbError>;
    async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse;
    async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse;
    async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse;
}
