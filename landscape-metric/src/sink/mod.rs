use landscape_common::database::error::DbError;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
    ConnectMetricPoint, IpHistoryStat, MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsMetric, DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_common::sys_config::ConnectMetricRuntimeConfig;

use crate::agg::Batch;
use crate::agg::dns_bucket::{DnsBucketRow, DnsSummaryParts};

pub(crate) mod memory;
#[cfg(feature = "metric-persistent")]
pub(crate) mod persistent;

#[async_trait::async_trait]
pub(crate) trait ConnectMetricSink: MetricStorage {
    async fn apply_connect_batch(&self, batch: &Batch) -> bool;
    async fn cleanup_connect(&self, config: &ConnectMetricRuntimeConfig);
    async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint>;
    async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> ConnectHistoryResponse;
    async fn history_src_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat>;
    async fn history_dst_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat>;
    async fn get_global_stats(&self, force_refresh: bool) -> Result<ConnectGlobalStats, DbError>;
}

#[async_trait::async_trait]
pub(crate) trait DnsMetricSink: MetricStorage {
    async fn apply_dns_batch(&self, metrics: Vec<DnsMetric>) -> bool;
    /// 追加写入 1m 预聚合桶行(dns_metrics_1m + top 表,纯 INSERT,同键冲突忽略)。
    /// 桶行由 DNS writer 从原始行批次构建后与原始行同批落库。
    async fn apply_dns_bucket_rows(&self, rows: Vec<DnsBucketRow>) -> bool;
    async fn cleanup_dns(&self, config: &landscape_common::sys_config::DnsMetricRuntimeConfig);
    async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse;
    async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse;
    /// 1m 预聚合桶摘要:按分钟对齐半开区间 [start_ms, end_ms) 从桶表聚合
    /// (逐行合并,不假设每分钟只有一行),仅服务仪表盘状态卡 DB 查询路径,
    /// 与内存窗口无关。调用方负责分钟对齐。
    async fn get_dns_summary_parts(
        &self,
        start_ms: u64,
        end_ms: u64,
        flow_id: Option<u32>,
    ) -> DnsSummaryParts;
}

#[async_trait::async_trait]
pub(crate) trait MetricStorage: Send + Sync {
    async fn close(&self);
}
