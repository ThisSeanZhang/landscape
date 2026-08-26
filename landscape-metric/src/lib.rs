use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use landscape_common::config::{MetricMode, MetricRuntimeConfig};
use landscape_common::database::error::DbError;
use landscape_common::event::{ConnectMessage, DnsMetricMessage};
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat, IpRealtimeStat,
    MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_core::time::get_current_time_ms;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub(crate) mod agg;
pub(crate) mod sink;
pub(crate) mod workers;

use agg::Batch;
pub use sink::memory::MemoryMetricStore;
pub mod memory_store {
    pub use crate::sink::memory::MemoryMetricStore;
}
use sink::memory::MemoryMetricSink;
#[cfg(feature = "metric-persistent")]
use sink::persistent::PersistentMetricStore;
use sink::MetricSink;

#[cfg(feature = "metric-persistent")]
use agg::dns_window::{minute_end, minute_start, DnsRecentWindow, DNS_RECENT_WINDOW_SECS};
#[cfg(feature = "metric-persistent")]
use landscape_common::metric::dns::DnsMetric;

/// 构建后端 sink:内存模式与 Off 模式挂 MemorySink;persistent 初始化失败时
/// 回退内存 sink,保证 metric 数据不影响系统启动。
/// 返回是否启用 DNS 实时窗口(persistent 后端成功初始化时为 true)。
#[cfg(feature = "metric-persistent")]
async fn build_sink(
    base_path: PathBuf,
    _config: &MetricRuntimeConfig,
    mode: &MetricMode,
) -> (Arc<dyn MetricSink>, bool) {
    match mode {
        MetricMode::Off | MetricMode::Memory => (Arc::new(MemoryMetricSink), false),
        MetricMode::Persistent => match PersistentMetricStore::new(base_path).await {
            Ok(store) => (Arc::new(store), true),
            Err(error) => {
                tracing::error!(
                    "failed to initialize persistent metric backend, falling back to memory: {}",
                    error
                );
                (Arc::new(MemoryMetricSink), false)
            }
        },
        // resolved_metric_mode 已把 duckdb 映射为 persistent/memory,不会走到这里。
        MetricMode::Duckdb => (Arc::new(MemoryMetricSink), false),
    }
}

#[cfg(not(feature = "metric-persistent"))]
async fn build_sink(
    _base_path: PathBuf,
    _config: &MetricRuntimeConfig,
    mode: &MetricMode,
) -> Arc<dyn MetricSink> {
    match mode {
        MetricMode::Off | MetricMode::Memory | MetricMode::Duckdb => Arc::new(MemoryMetricSink),
        MetricMode::Persistent => {
            tracing::error!(
                "metric mode 'persistent' requested, but landscape-metric was built \
                 without the metric-persistent feature; falling back to memory"
            );
            Arc::new(MemoryMetricSink)
        }
    }
}

/// 指标引擎:聚合层(内存实时态)+ sink 层(历史存储)通过管线串接。
/// 实时查询由聚合层内存态直接服务,历史查询转发给 sink。
#[derive(Clone)]
pub struct MetricEngine {
    config: MetricRuntimeConfig,
    sink: Arc<dyn MetricSink>,
    connect_tx: Option<mpsc::Sender<ConnectMessage>>,
    dns_tx: Option<mpsc::Sender<DnsMetricMessage>>,
    shutdown: CancellationToken,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    connect_writer_tx: Arc<Mutex<Option<workers::ConnectBatchTx>>>,
    connect_writer_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    #[cfg(feature = "metric-persistent")]
    dns_writer_tx: Arc<Mutex<Option<workers::DnsBatchTx>>>,
    #[cfg(feature = "metric-persistent")]
    dns_writer_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    writer_stats: workers::WriteQueueStats,
    flow_cache: agg::FlowCache,
    iface_realtime: agg::IfaceRealtimeCache,
    second_window_ms: u64,
    #[cfg(feature = "metric-persistent")]
    dns_window: Option<DnsRecentWindow>,
}

impl MetricEngine {
    pub async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Result<Self, String> {
        let mode = resolved_metric_mode(config.mode.clone());
        #[cfg(feature = "metric-persistent")]
        let (sink, is_persistent) = build_sink(base_path, &config, &mode).await;
        #[cfg(not(feature = "metric-persistent"))]
        let sink = build_sink(base_path, &config, &mode).await;

        let flow_cache: agg::FlowCache = Arc::new(RwLock::new(HashMap::new()));
        let iface_realtime: agg::IfaceRealtimeCache = Arc::new(RwLock::new(HashMap::new()));
        let shutdown = CancellationToken::new();
        let workers = Arc::new(Mutex::new(Vec::new()));
        let connect_writer_tx = Arc::new(Mutex::new(None));
        let connect_writer_handle = Arc::new(Mutex::new(None));
        #[cfg(feature = "metric-persistent")]
        let dns_writer_tx = Arc::new(Mutex::new(None));
        #[cfg(feature = "metric-persistent")]
        let dns_writer_handle = Arc::new(Mutex::new(None));
        let writer_stats = workers::WriteQueueStats::default();
        let second_window_ms = agg::second_window_ms(&config);

        #[cfg(feature = "metric-persistent")]
        let dns_window = if is_persistent { Some(DnsRecentWindow::new()) } else { None };

        let (connect_tx, connect_rx) = mpsc::channel::<ConnectMessage>(agg::CHANNEL_CAPACITY);
        let (dns_tx, dns_rx) = mpsc::channel::<DnsMetricMessage>(agg::CHANNEL_CAPACITY);

        if !matches!(mode, MetricMode::Off) {
            // connect/dns 各自的 sqlite 文件相互独立,拆成两条 writer 链路并行写;
            // cleanup 由各 writer 任务内的定时器执行,不再占用投递队列。
            let (connect_write_tx, connect_write_rx) = mpsc::channel::<Batch>(256);
            #[cfg(feature = "metric-persistent")]
            let (dns_write_tx, dns_write_rx) = mpsc::channel::<Vec<DnsMetric>>(256);
            let queue_stats = writer_stats.clone();
            let connect_writer_sink = sink.clone();
            let connect_writer_config = config.clone();
            let connect_writer_stats = queue_stats.clone();
            let connect_writer = tokio::spawn(async move {
                workers::run_connect_writer(
                    connect_writer_sink,
                    connect_write_rx,
                    connect_writer_stats,
                    connect_writer_config,
                )
                .await;
            });
            *connect_writer_tx.lock().expect("metric connect writer tx poisoned") =
                Some(connect_write_tx.clone());
            *connect_writer_handle.lock().expect("metric connect writer handle poisoned") =
                Some(connect_writer);

            #[cfg(feature = "metric-persistent")]
            {
                let dns_writer_sink = sink.clone();
                let dns_writer_config = config.clone();
                let dns_writer_stats = queue_stats.clone();
                let dns_writer = tokio::spawn(async move {
                    workers::run_dns_writer(
                        dns_writer_sink,
                        dns_write_rx,
                        dns_writer_stats,
                        dns_writer_config,
                    )
                    .await;
                });
                *dns_writer_tx.lock().expect("metric dns writer tx poisoned") =
                    Some(dns_write_tx.clone());
                *dns_writer_handle.lock().expect("metric dns writer handle poisoned") =
                    Some(dns_writer);
            }

            // 行为决策:启动不回填 DNS 最近窗口(不读回磁盘),重启后状态卡展示 0,
            // 直到新的 DNS 指标到达。避免高 QPS 下启动时一次性读回 5 分钟原始行的开销。
            let config_clone = config.clone();
            let flow_cache_clone = flow_cache.clone();
            let iface_realtime_clone = iface_realtime.clone();
            let shutdown_clone = shutdown.clone();
            let workers_clone = workers.clone();
            let write_tx_clone = connect_write_tx.clone();
            let queue_stats_clone = queue_stats.clone();
            let connect_handle = tokio::spawn(async move {
                workers::run_connect_worker(
                    connect_rx,
                    write_tx_clone,
                    queue_stats_clone,
                    config_clone,
                    flow_cache_clone,
                    iface_realtime_clone,
                    shutdown_clone,
                )
                .await;
            });
            workers_clone.lock().expect("metric workers poisoned").push(connect_handle);

            #[cfg(feature = "metric-persistent")]
            {
                let config_clone = config.clone();
                let shutdown_clone = shutdown.clone();
                let workers_clone = workers.clone();
                let dns_window_clone = dns_window.clone();
                let write_tx_clone = dns_write_tx.clone();
                let queue_stats_clone = queue_stats.clone();
                let dns_handle = tokio::spawn(async move {
                    workers::run_dns_worker(
                        dns_rx,
                        write_tx_clone,
                        queue_stats_clone,
                        config_clone,
                        dns_window_clone,
                        shutdown_clone,
                    )
                    .await;
                });
                workers_clone.lock().expect("metric workers poisoned").push(dns_handle);
            }

            #[cfg(not(feature = "metric-persistent"))]
            {
                let shutdown_clone = shutdown.clone();
                let workers_clone = workers.clone();
                let dns_handle = tokio::spawn(async move {
                    workers::run_dns_worker(dns_rx, shutdown_clone).await;
                });
                workers_clone.lock().expect("metric workers poisoned").push(dns_handle);
            }
        }

        Ok(Self {
            config,
            sink,
            connect_tx: if matches!(mode, MetricMode::Off) { None } else { Some(connect_tx) },
            dns_tx: if matches!(mode, MetricMode::Off) { None } else { Some(dns_tx) },
            shutdown,
            workers,
            connect_writer_tx,
            connect_writer_handle,
            #[cfg(feature = "metric-persistent")]
            dns_writer_tx,
            #[cfg(feature = "metric-persistent")]
            dns_writer_handle,
            writer_stats,
            flow_cache,
            iface_realtime,
            second_window_ms,
            #[cfg(feature = "metric-persistent")]
            dns_window,
        })
    }

    pub fn mode(&self) -> MetricMode {
        resolved_metric_mode(self.config.mode.clone())
    }

    pub fn get_connect_msg_channel(&self) -> Option<mpsc::Sender<ConnectMessage>> {
        self.connect_tx.clone()
    }

    pub fn get_dns_msg_channel(&self) -> Option<mpsc::Sender<DnsMetricMessage>> {
        self.dns_tx.clone()
    }

    /// Returns `(dropped_batches, failed_batches)` observed by the writer queue.
    pub fn writer_stats(&self) -> (u64, u64) {
        self.writer_stats.snapshot()
    }

    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        let handles: Vec<JoinHandle<()>> = {
            let mut workers = self.workers.lock().expect("metric workers poisoned");
            workers.drain(..).collect()
        };
        for handle in handles {
            let _ = handle.await;
        }
        // 聚合 worker 已退出(其持有的 writer sender 随之释放),再释放引擎侧的
        // sender,writer 消费完剩余批次后自然退出,保证 finalize 数据落库。
        let connect_writer_tx =
            self.connect_writer_tx.lock().expect("metric connect writer tx poisoned").take();
        drop(connect_writer_tx);
        let connect_writer_handle = self
            .connect_writer_handle
            .lock()
            .expect("metric connect writer handle poisoned")
            .take();
        if let Some(handle) = connect_writer_handle {
            let _ = handle.await;
        }
        #[cfg(feature = "metric-persistent")]
        {
            let dns_writer_tx =
                self.dns_writer_tx.lock().expect("metric dns writer tx poisoned").take();
            drop(dns_writer_tx);
            let dns_writer_handle =
                self.dns_writer_handle.lock().expect("metric dns writer handle poisoned").take();
            if let Some(handle) = dns_writer_handle {
                let _ = handle.await;
            }
        }
        self.sink.close().await;
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        agg::collect_connect_infos(&self.flow_cache, now_ms)
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        agg::collect_realtime_ip_stats(&self.flow_cache, now_ms, is_src)
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        agg::collect_realtime_iface_stats(&self.iface_realtime, now_ms)
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        if resolution == MetricResolution::Second {
            let cutoff =
                get_current_time_ms().unwrap_or_default().saturating_sub(self.second_window_ms);
            return agg::second_points_by_key(&self.flow_cache, &key, cutoff);
        }
        self.sink.query_metric_by_key(key, resolution).await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        self.sink.history_summaries_complex(params).await
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.sink.history_src_ip_stats(params).await
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.sink.history_dst_ip_stats(params).await
    }

    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        self.sink.get_global_stats(force_refresh).await
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        self.sink.query_dns_history(params).await
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        self.sink.get_dns_summary(params).await
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        #[cfg(feature = "metric-persistent")]
        if let Some(window) = &self.dns_window {
            let now_ms = get_current_time_ms().unwrap_or_default();
            return get_dns_lightweight_summary_from_window(window, &self.sink, params, now_ms)
                .await;
        }
        self.sink.get_dns_lightweight_summary(params).await
    }
}

#[cfg(feature = "metric-persistent")]
async fn get_dns_lightweight_summary_from_window(
    window: &DnsRecentWindow,
    sink: &Arc<dyn MetricSink>,
    mut params: DnsSummaryQueryParams,
    now_ms: u64,
) -> DnsLightweightSummaryResponse {
    let window_start = now_ms.saturating_sub(DNS_RECENT_WINDOW_SECS * 1000);
    if params.start_time == 0 && params.end_time == 0 {
        params.start_time = window_start;
        params.end_time = now_ms;
    } else if params.end_time == 0 {
        params.end_time = now_ms;
    }

    // 统一为分钟对齐的半开区间 [start, end)。内存窗口以整分钟桶为粒度,
    // 覆盖 [minute_start(now-5min), minute_end(now)),与 SQL 回退路径
    // 对同一区间的聚合语义一致,此处可安全命中内存。
    let start = minute_start(params.start_time);
    let end = minute_end(params.end_time);
    let window_start = minute_start(window_start);
    let window_end = minute_end(now_ms);
    if params.flow_id.is_none() && start >= window_start && end <= window_end {
        return window.lightweight_summary_range(start, end);
    }

    params.start_time = start;
    params.end_time = end;
    sink.get_dns_lightweight_summary(params).await
}

pub fn resolved_metric_mode(mode: MetricMode) -> MetricMode {
    if matches!(mode, MetricMode::Duckdb) {
        #[cfg(feature = "metric-persistent")]
        {
            MetricMode::Persistent
        }
        #[cfg(not(feature = "metric-persistent"))]
        {
            MetricMode::Memory
        }
    } else if matches!(mode, MetricMode::Persistent) {
        #[cfg(feature = "metric-persistent")]
        {
            mode
        }
        #[cfg(not(feature = "metric-persistent"))]
        {
            MetricMode::Memory
        }
    } else {
        mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
    #[cfg(feature = "metric-persistent")]
    use landscape_common::metric::dns::DnsOutcome;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn test_config(mode: MetricMode) -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode,
            connect_second_window_minutes: 5,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 7,
            connect_1d_retention_days: 30,
            dns_retention_days: 7,
            write_batch_size: 2,
            write_flush_interval_secs: 1,
            db_max_memory_mb: 128,
            db_max_threads: 1,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1_000,
            cleanup_slice_window_secs: 60,
        }
    }

    fn connect_metric(cpu_id: u32, report_time: u64, ingress_bytes: u64) -> ConnectMetric {
        ConnectMetric {
            key: ConnectKey { create_time: 1_000, cpu_id },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            src_port: 10_000 + cpu_id as u16,
            dst_port: 20_000 + cpu_id as u16,
            l4_proto: 6,
            l3_proto: 4,
            flow_id: cpu_id as u8,
            trace_id: cpu_id as u8,
            gress: 0,
            ifindex: cpu_id + 10,
            report_time,
            create_time_ms: report_time.saturating_sub(1_000),
            ingress_bytes,
            ingress_packets: ingress_bytes / 10,
            egress_bytes: ingress_bytes * 2,
            egress_packets: ingress_bytes / 5,
            status: ConnectStatusType::Active,
        }
    }

    #[cfg(feature = "metric-persistent")]
    fn dns_metric(report_time: u64) -> DnsMetricMessage {
        DnsMetricMessage::Metric(landscape_common::metric::dns::DnsMetric {
            flow_id: 1,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            response_code: "NOERROR".to_string(),
            status: DnsOutcome::Normal,
            report_time,
            duration_ms: 12,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            answers: Vec::new(),
        })
    }

    #[tokio::test]
    async fn memory_engine_serves_realtime_queries() {
        let engine =
            MetricEngine::new(PathBuf::new(), test_config(MetricMode::Memory)).await.unwrap();
        let tx = engine.get_connect_msg_channel().unwrap();
        let now_ms = get_current_time_ms().unwrap();

        tx.send(ConnectMessage::Metric(connect_metric(1, now_ms - 2_000, 100))).await.unwrap();
        tx.send(ConnectMessage::Metric(connect_metric(2, now_ms - 1_000, 200))).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let infos = engine.connect_infos().await;
            if infos.len() == 2 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for active flows");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let infos = engine.connect_infos().await;
        assert_eq!(infos[0].key.cpu_id, 2, "sorted by recency");
        assert!(infos[0].ingress_bps > 0);

        let ip_stats = engine.get_realtime_ip_stats(true).await;
        assert_eq!(ip_stats.len(), 1);
        assert_eq!(ip_stats[0].stats.active_conns, 2);

        let iface_stats = engine.get_realtime_iface_stats().await;
        assert_eq!(iface_stats.len(), 2);
        assert!(iface_stats.iter().all(|s| s.stats.active_conns == 1));

        // 内存模式历史查询返回空。
        let points = engine
            .query_metric_by_key(
                ConnectKey { create_time: 1_000, cpu_id: 1 },
                MetricResolution::Minute,
            )
            .await;
        assert!(points.is_empty());
        let stats = engine.get_global_stats(false).await.unwrap();
        assert_eq!(stats.total_connect_count, 0);

        engine.shutdown().await;
    }

    #[tokio::test]
    async fn memory_engine_second_resolution_served_from_ring() {
        let engine =
            MetricEngine::new(PathBuf::new(), test_config(MetricMode::Memory)).await.unwrap();
        let tx = engine.get_connect_msg_channel().unwrap();
        let now_ms = get_current_time_ms().unwrap();
        let key = ConnectKey { create_time: 1_000, cpu_id: 1 };

        tx.send(ConnectMessage::Metric(connect_metric(1, now_ms - 4_000, 100))).await.unwrap();
        tx.send(ConnectMessage::Metric(connect_metric(1, now_ms - 3_000, 200))).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let points = engine.query_metric_by_key(key.clone(), MetricResolution::Second).await;
            if points.len() == 2 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for ring points");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let points = engine.query_metric_by_key(key, MetricResolution::Second).await;
        assert_eq!(points.last().unwrap().ingress_bytes, 200);

        engine.shutdown().await;
    }

    #[tokio::test]
    async fn off_mode_exposes_no_channels() {
        let engine = MetricEngine::new(PathBuf::new(), test_config(MetricMode::Off)).await.unwrap();
        assert!(engine.get_connect_msg_channel().is_none());
        assert!(engine.get_dns_msg_channel().is_none());
        assert!(engine.connect_infos().await.is_empty());
        assert_eq!(engine.get_global_stats(false).await.unwrap().total_connect_count, 0);
        engine.shutdown().await;
    }

    #[tokio::test]
    async fn memory_shutdown_stops_worker() {
        let engine =
            MetricEngine::new(PathBuf::new(), test_config(MetricMode::Memory)).await.unwrap();
        let tx = engine.get_connect_msg_channel().unwrap();
        let now_ms = get_current_time_ms().unwrap();
        tx.send(ConnectMessage::Metric(connect_metric(1, now_ms - 1_000, 100))).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !engine.connect_infos().await.is_empty() {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for active flow");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let flow_cache = Arc::downgrade(&engine.flow_cache);
        engine.shutdown().await;
        drop(engine);

        tokio::time::timeout(Duration::from_secs(1), async {
            while flow_cache.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("metric worker did not stop after shutdown");
    }

    #[cfg(feature = "metric-persistent")]
    mod persistent {
        use super::*;

        #[tokio::test]
        async fn connect_pipeline_writes_summaries_buckets_and_global_stats() {
            let temp = tempfile::tempdir().unwrap();
            let engine =
                MetricEngine::new(temp.path().to_path_buf(), test_config(MetricMode::Persistent))
                    .await
                    .unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let now_ms = get_current_time_ms().unwrap();
            // 对齐到整分钟,避免两条 report_time 跨分钟边界落入不同 1m 桶导致断言 flaky。
            let minute_start = now_ms / 60_000 * 60_000;

            let mut active = connect_metric(1, minute_start - 2_000, 100);
            active.status = ConnectStatusType::Active;
            tx.send(ConnectMessage::Metric(active)).await.unwrap();
            let mut closed = connect_metric(1, minute_start - 1_000, 200);
            closed.status = ConnectStatusType::Disabled;
            tx.send(ConnectMessage::Metric(closed)).await.unwrap();

            let key = ConnectKey { create_time: 1_000, cpu_id: 1 };
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let stats = loop {
                let stats = engine.get_global_stats(false).await.unwrap();
                if stats.total_connect_count >= 1 {
                    break stats;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for summary persist"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            assert_eq!(stats.total_connect_count, 1);
            assert_eq!(stats.total_ingress_bytes, 200);
            assert_eq!(stats.total_egress_bytes, 400);

            let points = engine.query_metric_by_key(key.clone(), MetricResolution::Minute).await;
            assert_eq!(points.len(), 1);
            assert_eq!(points[0].ingress_bytes, 200);

            let history = engine
                .history_summaries_complex(ConnectHistoryQueryParams {
                    limit: Some(10),
                    ..Default::default()
                })
                .await;
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].key, key);

            engine.shutdown().await;
        }

        #[tokio::test]
        async fn dns_pipeline_updates_window_and_persists_to_sqlite() {
            let temp = tempfile::tempdir().unwrap();
            let engine =
                MetricEngine::new(temp.path().to_path_buf(), test_config(MetricMode::Persistent))
                    .await
                    .unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            let now_ms = get_current_time_ms().unwrap();

            tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let summary = loop {
                let summary =
                    engine.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
                if summary.total_queries >= 1 {
                    break summary;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for dns window ingest"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            assert_eq!(summary.total_queries, 1);
            assert_eq!(summary.total_v4, 1);
            assert_eq!(summary.avg_duration_ms, 12.0);

            let history = loop {
                let response = engine
                    .query_dns_history(DnsHistoryQueryParams {
                        limit: Some(10),
                        ..Default::default()
                    })
                    .await;
                if response.total >= 1 {
                    break response;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for dns persist"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            assert_eq!(history.items.len(), 1);
            assert_eq!(history.items[0].domain, "example.com");

            engine.shutdown().await;
        }

        #[tokio::test]
        async fn data_survives_engine_restart() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().to_path_buf();
            let now_ms = get_current_time_ms().unwrap();

            let engine =
                MetricEngine::new(path.clone(), test_config(MetricMode::Persistent)).await.unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let mut closed = connect_metric(1, now_ms - 1_000, 200);
            closed.status = ConnectStatusType::Disabled;
            tx.send(ConnectMessage::Metric(closed)).await.unwrap();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let stats = engine.get_global_stats(false).await.unwrap();
                if stats.total_connect_count >= 1 {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for summary persist"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            engine.shutdown().await;
            drop(engine);

            let restarted =
                MetricEngine::new(path, test_config(MetricMode::Persistent)).await.unwrap();
            let stats = restarted.get_global_stats(false).await.unwrap();
            assert_eq!(stats.total_connect_count, 1);
            assert_eq!(stats.total_ingress_bytes, 200);

            let history = restarted
                .history_summaries_complex(ConnectHistoryQueryParams {
                    limit: Some(10),
                    ..Default::default()
                })
                .await;
            assert_eq!(history.len(), 1);
            assert_eq!(history[0].total_ingress_bytes, 200);
            restarted.shutdown().await;
        }

        #[tokio::test]
        async fn dns_recent_window_agrees_with_sql_fallback_including_boundary_minute() {
            let temp = tempfile::tempdir().unwrap();
            let engine =
                MetricEngine::new(temp.path().to_path_buf(), test_config(MetricMode::Persistent))
                    .await
                    .unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            let now_ms = get_current_time_ms().unwrap();
            let window_start = minute_start(now_ms.saturating_sub(DNS_RECENT_WINDOW_SECS * 1000));

            // 边界区记录:report_time 早于 cutoff(now-5min)、但分钟桶恰落在窗口下界,
            // 内存窗口会保留它,SQL 回退也不会漏,两条路径结果一致。
            tx.send(dns_metric(window_start + 1)).await.unwrap();
            tx.send(dns_metric(now_ms - 60_000)).await.unwrap();
            tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let sql = engine
                    .get_dns_lightweight_summary(DnsSummaryQueryParams {
                        flow_id: Some(1),
                        ..Default::default()
                    })
                    .await;
                if sql.total_queries >= 3 {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for dns persist"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            // 同一区间:默认参数走内存窗口,flow_id 强制走 SQL 回退。
            let memory_summary =
                engine.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
            let sql_summary = engine
                .get_dns_lightweight_summary(DnsSummaryQueryParams {
                    flow_id: Some(1),
                    ..Default::default()
                })
                .await;
            assert_eq!(memory_summary.total_queries, 3);
            assert_eq!(memory_summary.total_queries, sql_summary.total_queries);
            assert_eq!(
                memory_summary.total_effective_queries, sql_summary.total_effective_queries,
                "memory window and SQL fallback must agree on the window range"
            );

            engine.shutdown().await;
        }

        #[tokio::test]
        async fn shutdown_finalizes_active_flows_and_flushes() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().to_path_buf();
            let now_ms = get_current_time_ms().unwrap();

            let engine =
                MetricEngine::new(path.clone(), test_config(MetricMode::Persistent)).await.unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let mut active = connect_metric(1, now_ms - 1_000, 200);
            active.status = ConnectStatusType::Active;
            tx.send(ConnectMessage::Metric(active)).await.unwrap();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                if !engine.connect_infos().await.is_empty() {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for active flow ingest"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            engine.shutdown().await;
            drop(engine);

            let restarted =
                MetricEngine::new(path, test_config(MetricMode::Persistent)).await.unwrap();
            let stats = restarted.get_global_stats(false).await.unwrap();
            assert_eq!(
                stats.total_connect_count, 1,
                "shutdown must finalize active flows into summaries"
            );
            assert_eq!(stats.total_ingress_bytes, 200);
            restarted.shutdown().await;
        }

        #[tokio::test]
        async fn dns_window_shows_zero_after_restart_until_new_metrics() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().to_path_buf();
            let now_ms = get_current_time_ms().unwrap();

            let engine =
                MetricEngine::new(path.clone(), test_config(MetricMode::Persistent)).await.unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                let history = engine
                    .query_dns_history(DnsHistoryQueryParams {
                        limit: Some(10),
                        ..Default::default()
                    })
                    .await;
                if history.total >= 1 {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for dns persist"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            engine.shutdown().await;
            drop(engine);

            let restarted =
                MetricEngine::new(path, test_config(MetricMode::Persistent)).await.unwrap();
            let summary =
                restarted.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
            assert_eq!(
                summary.total_queries, 0,
                "recent window intentionally not seeded from disk; shows 0 until new metrics arrive"
            );

            let tx = restarted.get_dns_msg_channel().unwrap();
            tx.send(dns_metric(now_ms - 1_000)).await.unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let summary = loop {
                let summary =
                    restarted.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
                if summary.total_queries >= 1 {
                    break summary;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "timed out waiting for dns window ingest"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            assert_eq!(summary.total_queries, 1);
            restarted.shutdown().await;
        }

        #[tokio::test]
        async fn shutdown_returns_promptly_while_connect_sender_alive() {
            let temp = tempfile::tempdir().unwrap();
            let engine =
                MetricEngine::new(temp.path().to_path_buf(), test_config(MetricMode::Persistent))
                    .await
                    .unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let now_ms = get_current_time_ms().unwrap();
            tx.send(ConnectMessage::Metric(connect_metric(1, now_ms - 1_000, 100))).await.unwrap();

            // 回归:shutdown 不得等待外部仍持活的 Sender 释放。修复前 drain 循环
            // 会因通道永不完全关闭而永久阻塞(store 自身字段亦持有 sender clone)。
            let result = tokio::time::timeout(Duration::from_secs(5), engine.shutdown()).await;
            assert!(result.is_ok(), "shutdown blocked while connect sender is still alive");

            drop(tx);
        }

        #[tokio::test]
        async fn shutdown_returns_promptly_while_dns_sender_alive() {
            let temp = tempfile::tempdir().unwrap();
            let engine =
                MetricEngine::new(temp.path().to_path_buf(), test_config(MetricMode::Persistent))
                    .await
                    .unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            let now_ms = get_current_time_ms().unwrap();
            tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

            // 回归:dns server(landscape-dns)会长期持有 sender 且晚于 metric 服务停止,
            // 修复前此处与真实 shutdown 场景一样永久阻塞。
            let result = tokio::time::timeout(Duration::from_secs(5), engine.shutdown()).await;
            assert!(result.is_ok(), "shutdown blocked while dns sender is still alive");

            drop(tx);
        }

        fn window_metric(report_time: u64) -> landscape_common::metric::dns::DnsMetric {
            let DnsMetricMessage::Metric(metric) = dns_metric(report_time);
            metric
        }

        #[tokio::test]
        async fn window_summary_completes_default_range_params() {
            let window = DnsRecentWindow::new();
            let sink: Arc<dyn MetricSink> = Arc::new(MemoryMetricSink);
            let now_ms = 100_000_000_000u64;
            window.ingest(&window_metric(now_ms - 1_000), now_ms);

            let summary = get_dns_lightweight_summary_from_window(
                &window,
                &sink,
                DnsSummaryQueryParams::default(),
                now_ms,
            )
            .await;
            assert_eq!(summary.total_queries, 1, "default (0,0) range completed and hit window");
            assert_eq!(summary.avg_duration_ms, 12.0);
        }

        #[tokio::test]
        async fn window_summary_completes_missing_end_time() {
            let window = DnsRecentWindow::new();
            let sink: Arc<dyn MetricSink> = Arc::new(MemoryMetricSink);
            let now_ms = 100_000_000_000u64;
            let report_time = minute_start(now_ms - 60_000) + 1;
            window.ingest(&window_metric(report_time), now_ms);

            let summary = get_dns_lightweight_summary_from_window(
                &window,
                &sink,
                DnsSummaryQueryParams {
                    start_time: minute_start(report_time),
                    end_time: 0,
                    flow_id: None,
                },
                now_ms,
            )
            .await;
            assert_eq!(summary.total_queries, 1, "end_time=0 completed to now and hit window");
        }

        #[tokio::test]
        async fn window_summary_falls_back_to_sink_when_filtered_or_out_of_range() {
            let window = DnsRecentWindow::new();
            let sink: Arc<dyn MetricSink> = Arc::new(MemoryMetricSink);
            let now_ms = 100_000_000_000u64;
            window.ingest(&window_metric(now_ms - 1_000), now_ms);

            let filtered = get_dns_lightweight_summary_from_window(
                &window,
                &sink,
                DnsSummaryQueryParams { flow_id: Some(1), ..Default::default() },
                now_ms,
            )
            .await;
            assert_eq!(filtered.total_queries, 0, "flow filter forces SQL fallback");

            let out_of_range = get_dns_lightweight_summary_from_window(
                &window,
                &sink,
                DnsSummaryQueryParams {
                    start_time: minute_start(now_ms - 2 * DNS_RECENT_WINDOW_SECS * 1000),
                    end_time: now_ms,
                    flow_id: None,
                },
                now_ms,
            )
            .await;
            assert_eq!(out_of_range.total_queries, 0, "range before window goes to SQL fallback");
        }
    }

    #[test]
    fn duckdb_metric_mode_resolves_to_persistent_or_memory() {
        let mode = resolved_metric_mode(MetricMode::Duckdb);

        #[cfg(feature = "metric-persistent")]
        assert!(matches!(mode, MetricMode::Persistent));

        #[cfg(not(feature = "metric-persistent"))]
        assert!(matches!(mode, MetricMode::Memory));
    }

    #[test]
    fn persistent_metric_mode_resolves_based_on_feature() {
        let mode = resolved_metric_mode(MetricMode::Persistent);

        #[cfg(feature = "metric-persistent")]
        assert!(matches!(mode, MetricMode::Persistent));

        #[cfg(not(feature = "metric-persistent"))]
        assert!(matches!(mode, MetricMode::Memory));
    }
}
