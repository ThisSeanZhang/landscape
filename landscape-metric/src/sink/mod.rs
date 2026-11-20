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
use crate::agg::dns_bucket::{DnsBucketRow, DnsSummaryParts, dns_bucket_rows_from_batch};

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
    ) -> Result<Vec<ConnectMetricPoint>, DbError>;
    async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Result<ConnectHistoryResponse, DbError>;
    async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Result<Vec<IpHistoryStat>, DbError>;
    async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Result<Vec<IpHistoryStat>, DbError>;
    async fn get_global_stats(&self, force_refresh: bool) -> Result<ConnectGlobalStats, DbError>;
}

/// One history write. Both representations are committed or rolled back together.
#[cfg_attr(not(any(feature = "metric-persistent", test)), allow(dead_code))]
pub(crate) struct DnsWriteBatch {
    pub metrics: Vec<DnsMetric>,
    pub buckets: Vec<DnsBucketRow>,
}

impl DnsWriteBatch {
    pub fn new(metrics: Vec<DnsMetric>) -> Self {
        let buckets = dns_bucket_rows_from_batch(&metrics);
        Self { metrics, buckets }
    }
}

#[async_trait::async_trait]
pub(crate) trait DnsMetricSink: MetricStorage {
    async fn apply_dns_batch(&self, batch: DnsWriteBatch) -> bool;
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
