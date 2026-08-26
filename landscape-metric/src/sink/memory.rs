use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::database::error::DbError;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat, IpRealtimeStat,
    MetricResolution,
};
#[cfg(feature = "metric-persistent")]
use landscape_common::metric::dns::DnsMetric;
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};

use landscape_common::event::{ConnectMessage, DnsMetricMessage};
use landscape_core::time::get_current_time_ms;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::MetricSink;
use crate::agg::{self, Batch, FlowCache, IfaceRealtimeCache};

/// 内存 sink:不落盘,丢弃聚合批次;历史查询返回空/默认值。
/// 实时查询(connect_infos / ip / iface / second 点)由聚合层内存态直接服务,
/// 因此内存模式仍具备完整实时能力,只是没有历史数据。
#[derive(Clone, Default)]
pub(crate) struct MemoryMetricSink;

#[async_trait::async_trait]
impl MetricSink for MemoryMetricSink {
    async fn apply_connect_batch(&self, _batch: &Batch) -> bool {
        true
    }

    #[cfg(feature = "metric-persistent")]
    async fn apply_dns_batch(&self, _metrics: Vec<DnsMetric>) -> bool {
        true
    }

    async fn cleanup_connect(&self, _config: &MetricRuntimeConfig) {}

    #[cfg(feature = "metric-persistent")]
    async fn cleanup_dns(&self, _config: &MetricRuntimeConfig) {}

    async fn close(&self) {}

    async fn query_metric_by_key(
        &self,
        _key: ConnectKey,
        _resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        Vec::new()
    }

    async fn history_summaries_complex(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        Vec::new()
    }

    async fn history_src_ip_stats(&self, _params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        Vec::new()
    }

    async fn history_dst_ip_stats(&self, _params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        Vec::new()
    }

    async fn get_global_stats(&self, _force_refresh: bool) -> Result<ConnectGlobalStats, DbError> {
        Ok(ConnectGlobalStats::default())
    }

    async fn query_dns_history(&self, _params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        DnsHistoryResponse::default()
    }

    async fn get_dns_summary(&self, _params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        DnsSummaryResponse::default()
    }

    async fn get_dns_lightweight_summary(
        &self,
        _params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        DnsLightweightSummaryResponse::default()
    }
}

/// Compatibility facade for the pre-pipeline public API.
#[derive(Clone)]
pub struct MemoryMetricStore {
    connect_tx: mpsc::Sender<ConnectMessage>,
    dns_tx: mpsc::Sender<DnsMetricMessage>,
    shutdown: CancellationToken,
    flow_cache: FlowCache,
    iface_realtime: IfaceRealtimeCache,
    second_window_ms: u64,
    _worker: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl MemoryMetricStore {
    pub async fn new(_base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let (connect_tx, mut connect_rx) = mpsc::channel(agg::CHANNEL_CAPACITY);
        let (dns_tx, mut dns_rx) = mpsc::channel(agg::CHANNEL_CAPACITY);
        let shutdown = CancellationToken::new();
        let flow_cache: FlowCache = Arc::new(RwLock::new(HashMap::new()));
        let iface_realtime: IfaceRealtimeCache = Arc::new(RwLock::new(HashMap::new()));
        let worker_shutdown = shutdown.clone();
        let worker_flow = flow_cache.clone();
        let worker_iface = iface_realtime.clone();
        let second_window_ms = agg::second_window_ms(&config);
        let second_ring_cap = agg::second_ring_capacity(&config);
        let cleanup_interval = Duration::from_secs(config.cleanup_interval_secs.max(1));
        let worker = tokio::spawn(async move {
            let mut cleanup_tick = tokio::time::interval(cleanup_interval);
            cleanup_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            cleanup_tick.tick().await;
            let mut connect_closed = false;
            let mut dns_closed = false;
            loop {
                tokio::select! {
                    _ = worker_shutdown.cancelled() => break,
                    _ = cleanup_tick.tick() => {
                        let now = get_current_time_ms().unwrap_or_default();
                        let _ = agg::cleanup_flow_cache(&worker_flow, &worker_iface, now, second_window_ms);
                    }
                    msg = connect_rx.recv(), if !connect_closed => match msg {
                        Some(ConnectMessage::Metric(metric)) => {
                            let _ = agg::process_connect_metric(&worker_flow, &worker_iface, metric, second_window_ms, second_ring_cap);
                        }
                        None => connect_closed = true,
                    },
                    msg = dns_rx.recv(), if !dns_closed => match msg {
                        Some(DnsMetricMessage::Metric(_)) => {}
                        None => dns_closed = true,
                    },
                }
                if connect_closed && dns_closed {
                    break;
                }
            }
        });

        Self {
            connect_tx,
            dns_tx,
            shutdown,
            flow_cache,
            iface_realtime,
            second_window_ms,
            _worker: Arc::new(Mutex::new(Some(worker))),
        }
    }

    pub fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        self.connect_tx.clone()
    }

    pub fn get_dns_msg_channel(&self) -> mpsc::Sender<DnsMetricMessage> {
        self.dns_tx.clone()
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        agg::collect_connect_infos(&self.flow_cache, get_current_time_ms().unwrap_or_default())
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        agg::collect_realtime_ip_stats(
            &self.flow_cache,
            get_current_time_ms().unwrap_or_default(),
            is_src,
        )
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        agg::collect_realtime_iface_stats(
            &self.iface_realtime,
            get_current_time_ms().unwrap_or_default(),
        )
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        if resolution != MetricResolution::Second {
            return Vec::new();
        }
        let cutoff =
            get_current_time_ms().unwrap_or_default().saturating_sub(self.second_window_ms);
        agg::second_points_by_key(&self.flow_cache, &key, cutoff)
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
    ) -> Vec<IpHistoryStat> {
        Vec::new()
    }
    pub async fn history_dst_ip_stats(
        &self,
        _params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        Vec::new()
    }
    pub async fn get_global_stats(
        &self,
        _force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        Ok(ConnectGlobalStats::default())
    }
    pub async fn query_dns_history(&self, _params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        DnsHistoryResponse::default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::config::MetricMode;
    use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: MetricMode::Memory,
            connect_second_window_minutes: 5,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 1,
            connect_1d_retention_days: 1,
            dns_retention_days: 1,
            write_batch_size: 16,
            write_flush_interval_secs: 1,
            db_max_memory_mb: 64,
            db_max_threads: 1,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1000,
            cleanup_slice_window_secs: 60,
        }
    }

    fn test_metric(report_time: u64) -> ConnectMetric {
        ConnectMetric {
            key: ConnectKey { create_time: 1, cpu_id: 1 },
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 1000,
            dst_port: 2000,
            l4_proto: 6,
            l3_proto: 4,
            flow_id: 1,
            trace_id: 1,
            gress: 0,
            ifindex: 2,
            report_time,
            create_time_ms: report_time.saturating_sub(1000),
            ingress_bytes: 100,
            ingress_packets: 10,
            egress_bytes: 200,
            egress_packets: 20,
            status: ConnectStatusType::Active,
        }
    }

    #[tokio::test]
    async fn compatibility_facade_serves_realtime_api() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let tx = store.get_connect_msg_channel();
        let now = get_current_time_ms().unwrap();
        tx.send(ConnectMessage::Metric(test_metric(now - 1000))).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let infos = store.connect_infos().await;
            if !infos.is_empty() {
                assert_eq!(infos[0].key.cpu_id, 1);
                assert!(infos[0].ingress_bps > 0);
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for metric");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let points = store
            .query_metric_by_key(ConnectKey { create_time: 1, cpu_id: 1 }, MetricResolution::Second)
            .await;
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].ingress_bytes, 100);
        store.shutdown();
    }

    /// 回归:store 未调用 shutdown 而被直接 drop 时,两个通道随之关闭,
    /// worker 必须通过 both-closed 分支退出;修复前若 recv 的 None 未被处理,
    /// select! 会反复立即完成导致空转占满 CPU。
    #[tokio::test]
    async fn facade_worker_exits_when_both_channels_close() {
        let store = MemoryMetricStore::new(PathBuf::new(), test_config()).await;
        let handle = store._worker.lock().unwrap().take().expect("facade worker handle");
        drop(store);

        let _ = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("facade worker must exit when both channels close");
    }
}
