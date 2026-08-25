pub(crate) mod dns_window;
mod sqlite;
mod workers;

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use landscape_common::config::MetricRuntimeConfig;
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
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ingest::{
    collect_connect_infos, collect_realtime_iface_stats, collect_realtime_ip_stats,
    second_points_by_key, second_window_ms, FlowCache, IfaceBucketCache, IfaceRealtimeCache,
    CHANNEL_CAPACITY,
};

use self::dns_window::{minute_end, minute_start, DnsRecentWindow, DNS_RECENT_WINDOW_SECS};

#[derive(Clone)]
pub(crate) struct PersistentMetricStore {
    connect_tx: mpsc::Sender<ConnectMessage>,
    dns_tx: mpsc::Sender<DnsMetricMessage>,
    shutdown: CancellationToken,
    workers: Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    flow_cache: FlowCache,
    second_window_ms: u64,
    dns_window: DnsRecentWindow,
    connect_pool: SqlitePool,
    dns_pool: SqlitePool,
}

impl PersistentMetricStore {
    pub(crate) async fn new(
        base_path: PathBuf,
        config: MetricRuntimeConfig,
    ) -> Result<Self, String> {
        if !base_path.exists() {
            std::fs::create_dir_all(&base_path).map_err(|error| {
                format!(
                    "failed to create persistent metric directory {}: {}",
                    base_path.display(),
                    error
                )
            })?;
        }

        let version = landscape_common::LANDSCAPE_METRIC_DB_VERSION;
        let connect_db_path = base_path.join(format!("metrics_v{version}_connect.sqlite"));
        let dns_db_path = base_path.join(format!("metrics_v{version}_dns.sqlite"));

        let connect_pool = sqlite::open_connect_pool(&connect_db_path).await?;
        let dns_pool = sqlite::open_dns_pool(&dns_db_path).await?;

        let (connect_tx, connect_rx) = mpsc::channel::<ConnectMessage>(CHANNEL_CAPACITY);
        let (dns_tx, dns_rx) = mpsc::channel::<DnsMetricMessage>(CHANNEL_CAPACITY);
        let shutdown = CancellationToken::new();

        let flow_cache: FlowCache = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let iface_realtime: IfaceRealtimeCache =
            Arc::new(RwLock::new(std::collections::HashMap::new()));
        let iface_buckets: IfaceBucketCache =
            Arc::new(RwLock::new(std::collections::HashMap::new()));
        let dns_window = DnsRecentWindow::new();

        // 行为决策:启动不回填 DNS 最近窗口(不读回磁盘),重启后状态卡展示 0,
        // 直到新的 DNS 指标到达。避免高 QPS 下启动时一次性读回 5 分钟原始行的开销。
        let workers = Arc::new(std::sync::Mutex::new(Vec::new()));

        let connect_pool_clone = connect_pool.clone();
        let connect_config = config.clone();
        let connect_cache = flow_cache.clone();
        let connect_iface_realtime = iface_realtime.clone();
        let connect_iface_buckets = iface_buckets.clone();
        let connect_shutdown = shutdown.clone();
        let connect_workers = workers.clone();
        let connect_handle = tokio::spawn(async move {
            workers::run_connect_worker(
                connect_rx,
                connect_pool_clone,
                connect_config,
                connect_cache,
                connect_iface_realtime,
                connect_iface_buckets,
                connect_shutdown,
            )
            .await;
        });
        connect_workers.lock().expect("persistent workers poisoned").push(connect_handle);

        let dns_pool_clone = dns_pool.clone();
        let dns_config = config.clone();
        let dns_window_clone = dns_window.clone();
        let dns_shutdown = shutdown.clone();
        let dns_workers = workers.clone();
        let dns_handle = tokio::spawn(async move {
            workers::run_dns_worker(
                dns_rx,
                dns_pool_clone,
                dns_config,
                dns_window_clone,
                dns_shutdown,
            )
            .await;
        });
        dns_workers.lock().expect("persistent workers poisoned").push(dns_handle);

        tracing::info!(
            "persistent metric store ready: connect_db={} dns_db={}",
            connect_db_path.display(),
            dns_db_path.display()
        );

        Ok(Self {
            connect_tx,
            dns_tx,
            shutdown,
            workers,
            flow_cache,
            second_window_ms: second_window_ms(&config),
            dns_window,
            connect_pool,
            dns_pool,
        })
    }

    pub fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        self.connect_tx.clone()
    }

    pub fn get_dns_msg_channel(&self) -> mpsc::Sender<DnsMetricMessage> {
        self.dns_tx.clone()
    }

    pub async fn shutdown(&self) {
        self.shutdown.cancel();
        let handles: Vec<JoinHandle<()>> = {
            let mut workers = self.workers.lock().expect("persistent workers poisoned");
            workers.drain(..).collect()
        };
        for handle in handles {
            let _ = handle.await;
        }
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        collect_connect_infos(&self.flow_cache, now_ms)
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        collect_realtime_ip_stats(&self.flow_cache, now_ms, is_src)
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        collect_realtime_iface_stats(&self.flow_cache, now_ms)
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        if resolution == MetricResolution::Second {
            let cutoff =
                get_current_time_ms().unwrap_or_default().saturating_sub(self.second_window_ms);
            return second_points_by_key(&self.flow_cache, &key, cutoff);
        }

        match sqlite::connect::query_metric_by_key(&self.connect_pool, &key, resolution).await {
            Ok(points) => points,
            Err(error) => {
                tracing::error!("failed to query persistent connect metrics by key: {}", error);
                Vec::new()
            }
        }
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        match sqlite::connect::query_historical_summaries_complex(&self.connect_pool, params).await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect history summaries: {}", error);
                Vec::new()
            }
        }
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        match sqlite::connect::query_connection_ip_history(&self.connect_pool, params, true).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect src ip history: {}", error);
                Vec::new()
            }
        }
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        match sqlite::connect::query_connection_ip_history(&self.connect_pool, params, false).await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect dst ip history: {}", error);
                Vec::new()
            }
        }
    }

    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        if force_refresh {
            sqlite::connect::rebuild_global_stats_cache(&self.connect_pool).await.map_err(|error| {
                DbError::Internal(format!(
                    "failed to rebuild persistent connect global stats cache: {}",
                    error
                ))
            })
        } else {
            sqlite::connect::query_global_stats(&self.connect_pool).await.map_err(|error| {
                DbError::Internal(format!(
                    "failed to query persistent connect global stats cache: {}",
                    error
                ))
            })
        }
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        match sqlite::dns::query_dns_history(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns history: {}", error);
                DnsHistoryResponse::default()
            }
        }
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        match sqlite::dns::query_dns_summary(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns summary: {}", error);
                DnsSummaryResponse::default()
            }
        }
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        mut params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        let now_ms = get_current_time_ms().unwrap_or_default();
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
            return self.dns_window.lightweight_summary_range(start, end);
        }

        params.start_time = start;
        params.end_time = end;
        match sqlite::dns::query_dns_lightweight_summary(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns lightweight summary: {}", error);
                DnsLightweightSummaryResponse::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::config::MetricMode;
    use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
    use landscape_common::metric::dns::DnsOutcome;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn test_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: MetricMode::Persistent,
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
            status: ConnectStatusType::Disabled,
        }
    }

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
    async fn connect_pipeline_writes_summaries_buckets_and_global_stats() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            PersistentMetricStore::new(temp.path().to_path_buf(), test_config()).await.unwrap();
        let tx = store.get_connect_msg_channel();
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
            let stats = store.get_global_stats(false).await.unwrap();
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

        let points = store.query_metric_by_key(key.clone(), MetricResolution::Minute).await;
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].ingress_bytes, 200);

        let history = store
            .history_summaries_complex(ConnectHistoryQueryParams {
                limit: Some(10),
                ..Default::default()
            })
            .await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].key, key);

        store.shutdown().await;
    }

    #[tokio::test]
    async fn dns_pipeline_updates_window_and_persists_to_sqlite() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            PersistentMetricStore::new(temp.path().to_path_buf(), test_config()).await.unwrap();
        let tx = store.get_dns_msg_channel();
        let now_ms = get_current_time_ms().unwrap();

        tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let summary = loop {
            let summary = store.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
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
            let response = store
                .query_dns_history(DnsHistoryQueryParams { limit: Some(10), ..Default::default() })
                .await;
            if response.total >= 1 {
                break response;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for dns persist");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(history.items.len(), 1);
        assert_eq!(history.items[0].domain, "example.com");

        store.shutdown().await;
    }

    #[tokio::test]
    async fn data_survives_store_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_path_buf();
        let now_ms = get_current_time_ms().unwrap();

        let store = PersistentMetricStore::new(path.clone(), test_config()).await.unwrap();
        let tx = store.get_connect_msg_channel();
        let mut closed = connect_metric(1, now_ms - 1_000, 200);
        closed.status = ConnectStatusType::Disabled;
        tx.send(ConnectMessage::Metric(closed)).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let stats = store.get_global_stats(false).await.unwrap();
            if stats.total_connect_count >= 1 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for summary persist"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        store.shutdown().await;
        drop(store);

        let restarted = PersistentMetricStore::new(path, test_config()).await.unwrap();
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
        let store =
            PersistentMetricStore::new(temp.path().to_path_buf(), test_config()).await.unwrap();
        let tx = store.get_dns_msg_channel();
        let now_ms = get_current_time_ms().unwrap();
        let window_start = minute_start(now_ms.saturating_sub(DNS_RECENT_WINDOW_SECS * 1000));

        // 边界区记录:report_time 早于 cutoff(now-5min)、但分钟桶恰落在窗口下界,
        // 修复前内存窗口会丢弃它而 SQL 回退不会,两条路径结果不一致。
        tx.send(dns_metric(window_start + 1)).await.unwrap();
        tx.send(dns_metric(now_ms - 60_000)).await.unwrap();
        tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let sql = store
                .get_dns_lightweight_summary(DnsSummaryQueryParams {
                    flow_id: Some(1),
                    ..Default::default()
                })
                .await;
            if sql.total_queries >= 3 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for dns persist");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // 同一区间:默认参数走内存窗口,flow_id 强制走 SQL 回退。
        let memory_summary =
            store.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
        let sql_summary = store
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

        store.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_finalizes_active_flows_and_flushes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_path_buf();
        let now_ms = get_current_time_ms().unwrap();

        let store = PersistentMetricStore::new(path.clone(), test_config()).await.unwrap();
        let tx = store.get_connect_msg_channel();
        let mut active = connect_metric(1, now_ms - 1_000, 200);
        active.status = ConnectStatusType::Active;
        tx.send(ConnectMessage::Metric(active)).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !store.connect_infos().await.is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for active flow ingest"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        store.shutdown().await;
        drop(store);

        let restarted = PersistentMetricStore::new(path, test_config()).await.unwrap();
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

        let store = PersistentMetricStore::new(path.clone(), test_config()).await.unwrap();
        let tx = store.get_dns_msg_channel();
        tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let history = store
                .query_dns_history(DnsHistoryQueryParams { limit: Some(10), ..Default::default() })
                .await;
            if history.total >= 1 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for dns persist");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        store.shutdown().await;
        drop(store);

        let restarted = PersistentMetricStore::new(path, test_config()).await.unwrap();
        let summary = restarted.get_dns_lightweight_summary(DnsSummaryQueryParams::default()).await;
        assert_eq!(
            summary.total_queries, 0,
            "recent window intentionally not seeded from disk; shows 0 until new metrics arrive"
        );

        let tx = restarted.get_dns_msg_channel();
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
        let store =
            PersistentMetricStore::new(temp.path().to_path_buf(), test_config()).await.unwrap();
        let tx = store.get_connect_msg_channel();
        let now_ms = get_current_time_ms().unwrap();
        tx.send(ConnectMessage::Metric(connect_metric(1, now_ms - 1_000, 100))).await.unwrap();

        // 回归:shutdown 不得等待外部仍持活的 Sender 释放。修复前 drain 循环
        // 会因通道永不完全关闭而永久阻塞(store 自身字段亦持有 sender clone)。
        let result = tokio::time::timeout(Duration::from_secs(5), store.shutdown()).await;
        assert!(result.is_ok(), "shutdown blocked while connect sender is still alive");

        drop(tx);
    }

    #[tokio::test]
    async fn shutdown_returns_promptly_while_dns_sender_alive() {
        let temp = tempfile::tempdir().unwrap();
        let store =
            PersistentMetricStore::new(temp.path().to_path_buf(), test_config()).await.unwrap();
        let tx = store.get_dns_msg_channel();
        let now_ms = get_current_time_ms().unwrap();
        tx.send(dns_metric(now_ms - 1_000)).await.unwrap();

        // 回归:dns server(landscape-dns)会长期持有 sender 且晚于 metric 服务停止,
        // 修复前此处与真实 shutdown 场景一样永久阻塞。
        let result = tokio::time::timeout(Duration::from_secs(5), store.shutdown()).await;
        assert!(result.is_ok(), "shutdown blocked while dns sender is still alive");

        drop(tx);
    }
}
