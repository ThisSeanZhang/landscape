use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::database::error::DbError;
use landscape_common::metric::connect::ConnectMetric;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
    ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat, IpRealtimeStat,
    MetricResolution,
};
use landscape_common::metric::dns::DnsMetricEvent;
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsLiveDashboard,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_common::sys_config::{
    ConnectMetricRuntimeConfig, DnsMetricRuntimeConfig, MetricStoreBackend,
};
use landscape_common::utils::time::now_ms;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub(crate) mod agg;
pub mod self_monitor_store;
pub(crate) mod sink;
pub(crate) mod workers;

use agg::Batch;
pub use sink::memory::MemoryMetricStore;
pub mod memory_store {
    pub use crate::sink::memory::MemoryMetricStore;
}
#[cfg(feature = "metric-persistent")]
use sink::persistent::PersistentMetricStore;
use sink::{ConnectMetricSink, DnsMetricSink};

use agg::dns_bucket::{minute_end, minute_start};
use agg::dns_window::{DNS_RECENT_WINDOW_SECS, DnsRecentWindow};

#[cfg(feature = "metric-persistent")]
#[derive(Clone, Copy, Debug)]
pub(crate) enum MetricKind {
    Connect,
    Dns,
}

#[derive(Default)]
struct Workers {
    stats: workers::WriteQueueStats,
    stop: CancellationToken,
    tasks: tokio::sync::Mutex<Vec<JoinHandle<()>>>,
}
impl Workers {
    async fn shutdown(&self) {
        self.stop.cancel();
        let mut tasks = self.tasks.lock().await;
        for task in tasks.drain(..) {
            let _ = task.await;
        }
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

pub struct ConnectMetricEngine {
    sink: Option<Arc<dyn ConnectMetricSink>>,
    connect_tx: Option<mpsc::Sender<ConnectMetric>>,
    workers: Workers,
    flow_cache: agg::FlowCache,
    iface_realtime: agg::IfaceRealtimeCache,
    second_window_ms: u64,
}

impl ConnectMetricEngine {
    pub fn off() -> Self {
        Self {
            sink: None,
            connect_tx: None,
            workers: Workers::default(),
            flow_cache: Arc::new(RwLock::new(HashMap::new())),
            iface_realtime: Arc::new(RwLock::new(HashMap::new())),
            second_window_ms: 0,
        }
    }
    pub async fn new(path: PathBuf, config: ConnectMetricRuntimeConfig) -> Result<Self, String> {
        if !config.enabled {
            return Ok(Self::off());
        }
        let sink: Option<Arc<dyn ConnectMetricSink>> = match config.store.backend {
            MetricStoreBackend::Memory => None,
            MetricStoreBackend::Sqlite => {
                #[cfg(feature = "metric-persistent")]
                {
                    Some(Arc::new(
                        PersistentMetricStore::open(
                            path,
                            MetricKind::Connect,
                            config.store.max_bytes,
                        )
                        .await?,
                    ))
                }
                #[cfg(not(feature = "metric-persistent"))]
                {
                    let _ = path;
                    return Err(
                        landscape_common::metric::MetricError::SqliteUnavailable.to_string()
                    );
                }
            }
        };
        Ok(Self { sink, ..Self::off() }.start(config))
    }

    fn start(mut self, config: ConnectMetricRuntimeConfig) -> Self {
        self.second_window_ms = agg::second_window_ms(&config);
        let stats = self.workers.stats.clone();
        let (tx, rx) = mpsc::channel(agg::CHANNEL_CAPACITY);
        let writer_tx = self.sink.as_ref().map(|sink| {
            let (writer_tx, writer_rx) = mpsc::channel::<Batch>(256);
            let writer = spawn_task(
                task_label::task::METRIC_CONNECT_WRITER,
                workers::run_connect_writer(sink.clone(), writer_rx, stats.clone(), config.clone()),
            );
            self.workers.tasks.get_mut().push(writer);
            writer_tx
        });
        let worker = spawn_task(
            task_label::task::METRIC_CONNECT_WORKER,
            workers::run_connect_worker(
                rx,
                writer_tx,
                stats,
                config,
                self.flow_cache.clone(),
                self.iface_realtime.clone(),
                self.workers.stop.clone(),
            ),
        );
        self.workers.tasks.get_mut().insert(0, worker);
        self.connect_tx = Some(tx);
        self
    }
    pub fn get_connect_msg_channel(&self) -> Option<mpsc::Sender<ConnectMetric>> {
        self.connect_tx.clone()
    }
    pub fn writer_stats(&self) -> (u64, u64) {
        self.workers.stats.snapshot()
    }
    pub async fn shutdown(&self) {
        self.workers.shutdown().await;
        if let Some(sink) = &self.sink {
            sink.close().await;
        }
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        let now_ms = now_ms();
        agg::collect_connect_infos(&self.flow_cache, now_ms)
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        let now_ms = now_ms();
        agg::collect_realtime_ip_stats(&self.flow_cache, now_ms, is_src)
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        let now_ms = now_ms();
        agg::collect_realtime_iface_stats(&self.iface_realtime, now_ms)
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        if resolution == MetricResolution::Second {
            let cutoff = now_ms().saturating_sub(self.second_window_ms);
            return agg::second_points_by_key(&self.flow_cache, &key, cutoff);
        }
        match &self.sink {
            Some(sink) => sink.query_metric_by_key(key, resolution).await,
            None => Default::default(),
        }
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> ConnectHistoryResponse {
        match &self.sink {
            Some(sink) => sink.history_summaries_complex(params).await,
            None => Default::default(),
        }
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        match &self.sink {
            Some(sink) => sink.history_src_ip_stats(params).await,
            None => Default::default(),
        }
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        match &self.sink {
            Some(sink) => sink.history_dst_ip_stats(params).await,
            None => Default::default(),
        }
    }

    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        match &self.sink {
            Some(sink) => sink.get_global_stats(force_refresh).await,
            None => Ok(Default::default()),
        }
    }
}

pub struct DnsMetricEngine {
    sink: Option<Arc<dyn DnsMetricSink>>,
    dns_tx: Option<mpsc::Sender<DnsMetricEvent>>,
    workers: Workers,
    dns_window: DnsRecentWindow,
}

impl DnsMetricEngine {
    pub fn off() -> Self {
        Self {
            sink: None,
            dns_tx: None,
            workers: Workers::default(),
            dns_window: DnsRecentWindow::new(),
        }
    }
    pub async fn new(path: PathBuf, config: DnsMetricRuntimeConfig) -> Result<Self, String> {
        if !config.enabled {
            return Ok(Self::off());
        }
        let sink: Option<Arc<dyn DnsMetricSink>> = match config.store.backend {
            MetricStoreBackend::Memory => None,
            MetricStoreBackend::Sqlite => {
                #[cfg(feature = "metric-persistent")]
                {
                    Some(Arc::new(
                        PersistentMetricStore::open(path, MetricKind::Dns, config.store.max_bytes)
                            .await?,
                    ))
                }
                #[cfg(not(feature = "metric-persistent"))]
                {
                    let _ = path;
                    return Err(
                        landscape_common::metric::MetricError::SqliteUnavailable.to_string()
                    );
                }
            }
        };
        Ok(Self { sink, ..Self::off() }.start(config))
    }

    fn start(mut self, config: DnsMetricRuntimeConfig) -> Self {
        let stats = self.workers.stats.clone();
        let (tx, rx) = mpsc::channel(agg::CHANNEL_CAPACITY);
        let writer_tx = self.sink.as_ref().map(|sink| {
            let (writer_tx, writer_rx) = mpsc::channel(256);
            let writer = spawn_task(
                task_label::task::METRIC_DNS_WRITER,
                workers::dns::run_dns_writer(
                    sink.clone(),
                    writer_rx,
                    stats.clone(),
                    config.clone(),
                ),
            );
            self.workers.tasks.get_mut().push(writer);
            writer_tx
        });
        let worker = spawn_task(
            task_label::task::METRIC_DNS_WORKER,
            workers::dns::run_dns_worker(
                rx,
                writer_tx,
                stats,
                config,
                self.dns_window.clone(),
                self.workers.stop.clone(),
            ),
        );
        self.workers.tasks.get_mut().insert(0, worker);
        self.dns_tx = Some(tx);
        self
    }
    pub fn get_dns_msg_channel(&self) -> Option<mpsc::Sender<DnsMetricEvent>> {
        self.dns_tx.clone()
    }
    pub fn writer_stats(&self) -> (u64, u64) {
        self.workers.stats.snapshot()
    }
    pub async fn shutdown(&self) {
        self.workers.shutdown().await;
        if let Some(sink) = &self.sink {
            sink.close().await;
        }
    }

    pub fn get_dns_live_dashboard(&self, flow_id: Option<u32>) -> DnsLiveDashboard {
        self.dns_window.dashboard(now_ms(), flow_id)
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        match &self.sink {
            Some(sink) => sink.query_dns_history(params).await,
            None => Default::default(),
        }
    }

    /// Homepage counts come from the recent in-memory window in every storage mode.
    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        let Some((start, end)) = normalized_dns_range(&params, now_ms()) else {
            return Default::default();
        };
        self.dns_window.range_parts(start, end, params.flow_id).into_lightweight_response()
    }

    /// Dashboard history uses minute buckets, falling back to raw rows for a sub-minute range.
    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        let Some(sink) = &self.sink else { return Default::default() };
        if let Some((start, end)) = normalized_dns_range(&params, now_ms()) {
            return sink
                .get_dns_summary_parts(start, end, params.flow_id)
                .await
                .into_summary_response();
        }
        sink.get_dns_summary(params).await
    }
}

/// 将查询参数归一为分钟对齐的半开区间 [start, end)。
/// 默认 (0,0) 补全为最近 5 分钟;归一后 start >= end(倒置区间)时返回 None,
/// 由调用方处理:lightweight 返回空,summary 回退原始行。
fn normalized_dns_range(params: &DnsSummaryQueryParams, now_ms: u64) -> Option<(u64, u64)> {
    let (mut start_time, mut end_time) = (params.start_time, params.end_time);
    if start_time == 0 && end_time == 0 {
        start_time = now_ms.saturating_sub(DNS_RECENT_WINDOW_SECS * 1000);
        end_time = now_ms;
    } else if end_time == 0 {
        end_time = now_ms;
    }
    let start = minute_start(start_time);
    let end = minute_end(end_time);
    if start >= end {
        return None;
    }
    Some((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use landscape_common::sys_config::{ConnectMetricConfig, DnsMetricConfig, RuntimeConfigSource};
    fn connect_config(backend: MetricStoreBackend) -> ConnectMetricRuntimeConfig {
        let mut config = ConnectMetricConfig::default().build_runtime();
        config.store.backend = backend;
        config.write_batch_size = 2;
        config.store.write_flush_interval_secs = 1;
        config.store.cleanup_interval_secs = 3600;
        config
    }
    fn dns_config(backend: MetricStoreBackend) -> DnsMetricRuntimeConfig {
        let mut config = DnsMetricConfig::default().build_runtime();
        config.store.backend = backend;
        config.store.write_flush_interval_secs = 1;
        config.store.cleanup_interval_secs = 3600;
        config
    }

    fn connect_metric(
        cpu_id: u32,
        create_time_ms: u64,
        report_time: u64,
        ingress_bytes: u64,
    ) -> ConnectMetric {
        ConnectMetric::from_domain(
            create_time_ms,
            cpu_id,
            report_time,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            10_000 + cpu_id as u16,
            20_000 + cpu_id as u16,
            cpu_id as u8,
            cpu_id as u8,
            cpu_id + 10,
            ingress_bytes,
            ingress_bytes / 10,
            ingress_bytes * 2,
            ingress_bytes / 5,
            ConnectStatusType::Active,
        )
    }

    #[tokio::test]
    async fn memory_engine_serves_realtime_queries() {
        let engine =
            ConnectMetricEngine::new(PathBuf::new(), connect_config(MetricStoreBackend::Memory))
                .await
                .unwrap();
        let tx = engine.get_connect_msg_channel().unwrap();
        let now_ms = now_ms();

        tx.send(connect_metric(1, now_ms - 3_000, now_ms - 2_000, 100)).await.unwrap();
        tx.send(connect_metric(2, now_ms - 2_000, now_ms - 1_000, 200)).await.unwrap();

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

        // 内存模式历史查询返回空(即使用真实存在于 flow cache 的 key)。
        let points = engine
            .query_metric_by_key(
                ConnectKey {
                    create_time: (now_ms - 3_000) * 1_000_000,
                    cpu_id: 1,
                },
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
            ConnectMetricEngine::new(PathBuf::new(), connect_config(MetricStoreBackend::Memory))
                .await
                .unwrap();
        let tx = engine.get_connect_msg_channel().unwrap();
        let now_ms = now_ms();
        let key = ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 1 };

        tx.send(connect_metric(1, 1_000, now_ms - 4_000, 100)).await.unwrap();
        tx.send(connect_metric(1, 1_000, now_ms - 3_000, 200)).await.unwrap();

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
        let connect = ConnectMetricEngine::off();
        let dns = DnsMetricEngine::off();
        assert!(connect.get_connect_msg_channel().is_none());
        assert!(dns.get_dns_msg_channel().is_none());
        assert!(connect.connect_infos().await.is_empty());
        connect.shutdown().await;
        dns.shutdown().await;
    }

    #[tokio::test]
    async fn memory_shutdown_stops_worker() {
        let engine =
            ConnectMetricEngine::new(PathBuf::new(), connect_config(MetricStoreBackend::Memory))
                .await
                .unwrap();
        let tx = engine.get_connect_msg_channel().unwrap();
        let now_ms = now_ms();
        tx.send(connect_metric(1, 1_000, now_ms - 1_000, 100)).await.unwrap();

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
        use hickory_proto::op::ResponseCode;
        use hickory_proto::rr::RecordType;
        use landscape_common::metric::dns::{DnsMetricEvent, DnsOutcome};

        fn dns_metric(report_time: u64) -> DnsMetricEvent {
            DnsMetricEvent {
                flow_id: 1,
                domain: Arc::from("example.com"),
                query_type: RecordType::A,
                response_code: ResponseCode::NoError,
                status: DnsOutcome::Normal,
                report_time,
                duration_ms: 12,
                src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                answers: Vec::new(),
            }
        }

        #[tokio::test]
        async fn connect_pipeline_writes_summaries_buckets_and_global_stats() {
            let temp = tempfile::tempdir().unwrap();
            let engine = ConnectMetricEngine::new(
                temp.path().to_path_buf(),
                connect_config(MetricStoreBackend::Sqlite),
            )
            .await
            .unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let now_ms = now_ms();
            // 对齐到整分钟,避免两条 report_time 跨分钟边界落入不同 1m 桶导致断言 flaky。
            let minute_start = now_ms / 60_000 * 60_000;

            let mut active = connect_metric(1, 1_000, minute_start - 2_000, 100);
            active.status = ConnectStatusType::Active.into();
            tx.send(active).await.unwrap();
            let mut closed = connect_metric(1, 1_000, minute_start - 1_000, 200);
            closed.status = ConnectStatusType::Disabled.into();
            tx.send(closed).await.unwrap();

            let key = ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 1 };
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
            assert_eq!(history.items.len(), 1);
            assert_eq!(history.items[0].key, key);

            engine.shutdown().await;
        }

        #[tokio::test]
        async fn dns_pipeline_updates_window_and_persists_to_sqlite() {
            let temp = tempfile::tempdir().unwrap();
            let engine = DnsMetricEngine::new(
                temp.path().to_path_buf(),
                dns_config(MetricStoreBackend::Sqlite),
            )
            .await
            .unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            let now_ms = now_ms();

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
            let now_ms = now_ms();

            let engine =
                ConnectMetricEngine::new(path.clone(), connect_config(MetricStoreBackend::Sqlite))
                    .await
                    .unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let mut closed = connect_metric(1, 1_000, now_ms - 1_000, 200);
            closed.status = ConnectStatusType::Disabled.into();
            tx.send(closed).await.unwrap();

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
                ConnectMetricEngine::new(path, connect_config(MetricStoreBackend::Sqlite))
                    .await
                    .unwrap();
            let stats = restarted.get_global_stats(false).await.unwrap();
            assert_eq!(stats.total_connect_count, 1);
            assert_eq!(stats.total_ingress_bytes, 200);

            let history = restarted
                .history_summaries_complex(ConnectHistoryQueryParams {
                    limit: Some(10),
                    ..Default::default()
                })
                .await;
            assert_eq!(history.items.len(), 1);
            assert_eq!(history.items[0].total_ingress_bytes, 200);
            restarted.shutdown().await;
        }

        #[tokio::test]
        async fn dns_recent_window_agrees_with_sql_fallback_including_boundary_minute() {
            let temp = tempfile::tempdir().unwrap();
            let engine = DnsMetricEngine::new(
                temp.path().to_path_buf(),
                dns_config(MetricStoreBackend::Sqlite),
            )
            .await
            .unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            let now_ms = now_ms();
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
            let now_ms = now_ms();

            let engine =
                ConnectMetricEngine::new(path.clone(), connect_config(MetricStoreBackend::Sqlite))
                    .await
                    .unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let mut active = connect_metric(1, 1_000, now_ms - 1_000, 200);
            active.status = ConnectStatusType::Active.into();
            tx.send(active).await.unwrap();

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
                ConnectMetricEngine::new(path, connect_config(MetricStoreBackend::Sqlite))
                    .await
                    .unwrap();
            let stats = restarted.get_global_stats(false).await.unwrap();
            assert_eq!(
                stats.total_connect_count, 1,
                "shutdown must finalize active flows into summaries"
            );
            assert_eq!(stats.total_ingress_bytes, 200);
            restarted.shutdown().await;
        }

        #[tokio::test]
        async fn dns_summary_served_from_buckets_after_restart() {
            // 仪表盘状态卡(get_dns_summary)直查 DB 桶:重启后仍可读重启前的数据;
            // 首页卡片(get_dns_lightweight_summary)只读内存窗口:重启后为空返回 0,
            // 新流量进入窗口后恢复。两条数据路径相互独立。
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().to_path_buf();
            let now_ms = now_ms();

            let engine = DnsMetricEngine::new(path.clone(), dns_config(MetricStoreBackend::Sqlite))
                .await
                .unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

            // 等原始行落库(writer 同批构建桶行,桶随原始行一起持久化)。
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

            // 重启后:仪表盘状态卡从 DB 桶读到重启前的数据(桶在 DB,与窗口无关)。
            let restarted =
                DnsMetricEngine::new(path, dns_config(MetricStoreBackend::Sqlite)).await.unwrap();
            let summary = restarted.get_dns_summary(DnsSummaryQueryParams::default()).await;
            assert_eq!(
                summary.total_queries, 1,
                "dashboard summary served from persisted buckets after restart"
            );

            // 首页卡片只读内存窗口:重启后窗口为空 → 0。
            let lightweight =
                restarted.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
            assert_eq!(lightweight.total_queries, 0, "homepage card reads memory window only");

            // 新流量进入窗口后首页卡片恢复。
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
            let engine = ConnectMetricEngine::new(
                temp.path().to_path_buf(),
                connect_config(MetricStoreBackend::Sqlite),
            )
            .await
            .unwrap();
            let tx = engine.get_connect_msg_channel().unwrap();
            let now_ms = now_ms();
            tx.send(connect_metric(1, 1_000, now_ms - 1_000, 100)).await.unwrap();

            // 回归:shutdown 不得等待外部仍持活的 Sender 释放。修复前 drain 循环
            // 会因通道永不完全关闭而永久阻塞(store 自身字段亦持有 sender clone)。
            let result = tokio::time::timeout(Duration::from_secs(5), engine.shutdown()).await;
            assert!(result.is_ok(), "shutdown blocked while connect sender is still alive");

            drop(tx);
        }

        #[tokio::test]
        async fn shutdown_returns_promptly_while_dns_sender_alive() {
            let temp = tempfile::tempdir().unwrap();
            let engine = DnsMetricEngine::new(
                temp.path().to_path_buf(),
                dns_config(MetricStoreBackend::Sqlite),
            )
            .await
            .unwrap();
            let tx = engine.get_dns_msg_channel().unwrap();
            let now_ms = now_ms();
            tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

            // 回归:dns server(landscape-dns)会长期持有 sender 且晚于 metric 服务停止,
            // 修复前此处与真实 shutdown 场景一样永久阻塞。
            let result = tokio::time::timeout(Duration::from_secs(5), engine.shutdown()).await;
            assert!(result.is_ok(), "shutdown blocked while dns sender is still alive");

            drop(tx);
        }

        fn window_metric(report_time: u64) -> landscape_common::metric::dns::DnsMetric {
            dns_metric(report_time).into_metric()
        }

        #[tokio::test]
        async fn dns_parts_complete_default_range_params() {
            let window = DnsRecentWindow::new();
            let now_ms = 100_000_000_000u64;
            window.ingest(&window_metric(now_ms - 1_000), now_ms);

            let (start, end) =
                normalized_dns_range(&DnsSummaryQueryParams::default(), now_ms).unwrap();
            let summary = window.range_parts(start, end, None).into_lightweight_response();
            assert_eq!(summary.total_queries, 1, "default (0,0) range completed and hit window");
            assert_eq!(summary.avg_duration_ms, 12.0);
        }

        #[tokio::test]
        async fn dns_parts_complete_missing_end_time() {
            let window = DnsRecentWindow::new();
            let now_ms = 100_000_000_000u64;
            let report_time = minute_start(now_ms - 60_000) + 1;
            window.ingest(&window_metric(report_time), now_ms);

            let (start, end) = normalized_dns_range(
                &DnsSummaryQueryParams {
                    start_time: minute_start(report_time),
                    end_time: 0,
                    flow_id: None,
                },
                now_ms,
            )
            .unwrap();
            let summary = window.range_parts(start, end, None).into_lightweight_response();
            assert_eq!(summary.total_queries, 1, "end_time=0 completed to now and hit window");
        }

        #[tokio::test]
        async fn dns_parts_window_only_never_merges_buckets() {
            let window = DnsRecentWindow::new();
            let now_ms = 100_000_000_000u64;
            window.ingest(&window_metric(now_ms - 60_000), now_ms);

            let (start, end) =
                normalized_dns_range(&DnsSummaryQueryParams::default(), now_ms).unwrap();
            let parts = window.range_parts(start, end, None);
            assert_eq!(parts.counts.total_queries, 1, "window-only data served");

            // 窗口不落库、查询不合并桶:跨越窗口下界的区间,更早部分在纯内存下不存在。
            let wide_start = minute_start(now_ms - 2 * DNS_RECENT_WINDOW_SECS * 1000);
            let parts = window.range_parts(wide_start, end, None);
            assert_eq!(parts.counts.total_queries, 1, "older part absent from memory-only window");
        }

        #[tokio::test]
        async fn dns_parts_filter_by_flow() {
            let window = DnsRecentWindow::new();
            let now_ms = 100_000_000_000u64;
            let minute = minute_start(now_ms);
            let mut metric = window_metric(minute + 10);
            metric.flow_id = 1;
            window.ingest(&metric, now_ms);
            let mut other = window_metric(minute + 20);
            other.flow_id = 2;
            window.ingest(&other, now_ms);

            let (start, end) =
                normalized_dns_range(&DnsSummaryQueryParams::default(), now_ms).unwrap();
            let flow_one = window.range_parts(start, end, Some(1));
            assert_eq!(flow_one.counts.total_queries, 1);
            let all = window.range_parts(start, end, None);
            assert_eq!(all.counts.total_queries, 2);
        }

        #[tokio::test]
        async fn dns_parts_subminute_range_returns_none() {
            let now_ms = 100_000_000_000u64;
            // 分钟内的短区间会被放宽到整个分钟(分钟粒度语义);
            // 倒置区间(起点晚于终点且跨分钟)归一后为空 → 回退原始行。
            let widened = normalized_dns_range(
                &DnsSummaryQueryParams {
                    start_time: now_ms - 10_000,
                    end_time: now_ms,
                    flow_id: None,
                },
                now_ms,
            );
            assert!(widened.is_some(), "sub-minute forward range widens to the whole minute");

            let inverted = normalized_dns_range(
                &DnsSummaryQueryParams {
                    start_time: now_ms,
                    end_time: now_ms - 60_000,
                    flow_id: None,
                },
                now_ms,
            );
            assert!(inverted.is_none(), "inverted cross-minute range must fall back to raw rows");
        }
    }

    #[tokio::test]
    async fn sqlite_requires_persistence_and_opens_only_the_requested_database() {
        let temp = tempfile::tempdir().unwrap();
        let engine =
            DnsMetricEngine::new(temp.path().into(), dns_config(MetricStoreBackend::Sqlite)).await;
        if !cfg!(feature = "metric-persistent") {
            assert!(engine.is_err());
            let connect = ConnectMetricEngine::new(
                temp.path().into(),
                connect_config(MetricStoreBackend::Sqlite),
            )
            .await;
            assert!(connect.is_err());
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
            return;
        }
        let engine = engine.unwrap();
        let names = std::fs::read_dir(temp.path())
            .unwrap()
            .map(|f| f.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(names.iter().all(|name| name.contains("_dns.sqlite")));
        assert!(!names.is_empty());
        engine.shutdown().await;
    }
}
