use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::event::ConnectMessage;
use landscape_common::utils::time::now_ms;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agg::flow::finalize_all_flows;
use crate::agg::{
    Batch, FlowCache, IfaceRealtimeCache, cleanup_flow_cache, process_connect_metric,
    second_ring_capacity, second_window_ms,
};
use crate::sink::MetricSink;

pub(crate) mod dns;

/// 聚合 worker 投递批次给对应 writer 的类型化通道。
/// cleanup 不再走队列,由各 writer 任务内的定时器直接执行。
pub(crate) type ConnectBatchTx = mpsc::Sender<Batch>;

#[derive(Clone, Default)]
pub(crate) struct WriteQueueStats {
    dropped_batches: Arc<AtomicU64>,
    failed_batches: Arc<AtomicU64>,
}

impl WriteQueueStats {
    fn dropped(&self) {
        let count = self.dropped_batches.fetch_add(1, Ordering::Relaxed) + 1;
        if count == 1 || count.is_power_of_two() {
            tracing::warn!("metric writer queue full; dropped_batches={}", count);
        }
    }

    fn failed(&self) {
        self.failed_batches.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> (u64, u64) {
        (self.dropped_batches.load(Ordering::Relaxed), self.failed_batches.load(Ordering::Relaxed))
    }
}

/// Connect 写入 worker:消费聚合批次落库,并按 cleanup 周期执行 connect 清理。
/// 与聚合 worker 解耦,写库/清理不阻塞聚合实时态;同一任务内批次与清理天然串行,
/// 避免与 SQLite 单写锁并发争抢。退出条件:通道关闭(所有 sender 释放)。
pub(crate) async fn run_connect_writer(
    sink: Arc<dyn MetricSink>,
    mut rx: mpsc::Receiver<Batch>,
    stats: WriteQueueStats,
    config: MetricRuntimeConfig,
) {
    let cleanup_interval_duration = Duration::from_secs(config.cleanup_interval_secs.max(1));
    let mut cleanup_interval = tokio::time::interval(cleanup_interval_duration);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup_interval.tick().await;

    let mut closed = false;
    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                sink.cleanup_connect(&config).await;
            }
            batch_opt = rx.recv(), if !closed => {
                match batch_opt {
                    Some(batch) => {
                        if !sink.apply_connect_batch(&batch).await {
                            stats.failed();
                        }
                    }
                    None => closed = true,
                }
            }
        }

        if closed {
            break;
        }
    }
}

fn flush_connect_batch(writer_tx: &ConnectBatchTx, stats: &WriteQueueStats, pending: &mut Batch) {
    if pending.is_empty() {
        return;
    }
    // 常规攒批路径用 try_send:队列满时批次被直接丢弃,避免写线程阻塞影响
    // 聚合实时性。shutdown 收尾路径(尤其 finalize_all_flows 结果)不经过这里,
    // 由 flush_connect_batch_on_shutdown 用 send().await(5s 超时)兜底。
    if writer_tx.try_send(std::mem::take(pending)).is_err() {
        stats.dropped();
    }
    *pending = Batch::default();
}

async fn flush_connect_batch_on_shutdown(
    writer_tx: &ConnectBatchTx,
    stats: &WriteQueueStats,
    pending: &mut Batch,
) {
    if pending.is_empty() {
        return;
    }
    let batch = std::mem::take(pending);
    let send_result = tokio::time::timeout(Duration::from_secs(5), writer_tx.send(batch)).await;
    if !matches!(send_result, Ok(Ok(()))) {
        stats.dropped();
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_connect_metric(
    writer_tx: &ConnectBatchTx,
    queue_stats: &WriteQueueStats,
    pending: &mut Batch,
    flow_cache: &FlowCache,
    iface_realtime: &IfaceRealtimeCache,
    metric: landscape_common::metric::connect::ConnectMetric,
    second_window: u64,
    second_ring_cap: usize,
    write_batch_size: usize,
) {
    let batch =
        process_connect_metric(flow_cache, iface_realtime, metric, second_window, second_ring_cap);
    pending.extend(batch);
    if pending.op_count() >= write_batch_size {
        flush_connect_batch(writer_tx, queue_stats, pending);
    }
}

/// Connect 聚合 worker:逐条聚合(flow cache 状态机)→ 攒批 → 投递 connect writer 队列。
pub(crate) async fn run_connect_worker(
    mut connect_rx: mpsc::Receiver<ConnectMessage>,
    writer_tx: ConnectBatchTx,
    queue_stats: WriteQueueStats,
    config: MetricRuntimeConfig,
    flow_cache: FlowCache,
    iface_realtime: IfaceRealtimeCache,
    shutdown: CancellationToken,
) {
    let cleanup_interval_duration = Duration::from_secs(config.cleanup_interval_secs.max(1));
    let flush_interval_duration = Duration::from_secs(config.write_flush_interval_secs.max(1));
    let write_batch_size = config.write_batch_size.max(1);
    let second_window = second_window_ms(&config);
    let second_ring_cap = second_ring_capacity(&config);

    let mut cleanup_interval = tokio::time::interval(cleanup_interval_duration);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup_interval.tick().await;
    let mut flush_interval = tokio::time::interval(flush_interval_duration);
    flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush_interval.tick().await;

    let mut pending = Batch::default();
    let mut connect_closed = false;

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                flush_connect_batch(&writer_tx, &queue_stats, &mut pending);

                let now_ms = now_ms();
                let (flow_stats, batch) = cleanup_flow_cache(
                    &flow_cache,
                    &iface_realtime,
                    now_ms,
                    second_window,
                );
                pending.extend(batch);
                flush_connect_batch(&writer_tx, &queue_stats, &mut pending);

                tracing::info!(
                    "phase=persistent_connect.cleanup active_flows={} finalized_flows={} finalized_in_run={} second_ring_points={}",
                    flow_stats.active_flows,
                    flow_stats.finalized_flows,
                    flow_stats.finalized_in_run,
                    flow_stats.second_ring_points,
                );
            }
            _ = flush_interval.tick() => {
                flush_connect_batch(&writer_tx, &queue_stats, &mut pending);
            }
            _ = shutdown.cancelled() => break,
            msg_opt = connect_rx.recv(), if !connect_closed => {
                match msg_opt {
                    Some(ConnectMessage::Metric(metric)) => {
                        handle_connect_metric(
                            &writer_tx,
                            &queue_stats,
                            &mut pending,
                            &flow_cache,
                            &iface_realtime,
                            metric,
                            second_window,
                            second_ring_cap,
                            write_batch_size,
                        );
                    }
                    None => connect_closed = true,
                }
            }
        }

        if connect_closed {
            break;
        }
    }

    connect_rx.close();
    // 退出前尽量消费通道内残留消息(正常停用场景通道很快关闭);若 shutdown
    // 已触发则立即退出,不等待外部仍持活的 Sender(dns server 等)释放,
    // 否则 recv() 会永久阻塞导致 shutdown/配置切换挂死。
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg_opt = connect_rx.recv() => match msg_opt {
                Some(ConnectMessage::Metric(metric)) => {
                    handle_connect_metric(
                        &writer_tx,
                        &queue_stats,
                        &mut pending,
                        &flow_cache,
                        &iface_realtime,
                        metric,
                        second_window,
                        second_ring_cap,
                        write_batch_size,
                    );
                }
                None => break,
            },
        }
    }

    flush_connect_batch_on_shutdown(&writer_tx, &queue_stats, &mut pending).await;

    let final_batch = finalize_all_flows(&flow_cache, &iface_realtime);
    pending.extend(final_batch);
    flush_connect_batch_on_shutdown(&writer_tx, &queue_stats, &mut pending).await;
}

#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, RwLock};

    use landscape_common::config::{MetricMode, MetricRuntimeConfig};
    use landscape_common::database::error::DbError;
    use landscape_common::metric::connect::{
        ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
        ConnectMetric, ConnectMetricPoint, ConnectStatusType, IpHistoryStat, MetricResolution,
    };
    use landscape_common::metric::dns::{
        DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
        DnsSummaryQueryParams, DnsSummaryResponse,
    };
    use landscape_common::metric::dns::{DnsMetric, DnsOutcome};

    use crate::agg::dns_bucket::DnsBucketRow;
    use crate::agg::dns_bucket::DnsSummaryParts;
    use crate::agg::{Batch, FlowCache, IfaceRealtimeCache};
    use crate::sink::MetricSink;

    pub(crate) fn test_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: MetricMode::Memory,
            connect_second_window_minutes: 5,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 7,
            connect_1d_retention_days: 30,
            connect_summary_retention_days: 30,
            connect_summary_max_rows: 0,
            connect_db_max_bytes: landscape_common::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES,
            dns_retention_days: 7,
            dns_1m_retention_days: 30,
            dns_db_max_bytes: landscape_common::DEFAULT_DNS_METRIC_DB_MAX_BYTES,
            write_batch_size: 2,
            write_flush_interval_secs: 3600,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1_000,
            cleanup_slice_window_secs: 60,
        }
    }

    pub(crate) fn connect_metric(
        cpu_id: u32,
        report_time: u64,
        ingress_bytes: u64,
    ) -> ConnectMetric {
        ConnectMetric::from_domain(
            1_000,
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

    pub(crate) fn closed_metric(
        cpu_id: u32,
        report_time: u64,
        ingress_bytes: u64,
    ) -> ConnectMetric {
        let mut metric = connect_metric(cpu_id, report_time, ingress_bytes);
        metric.status = ConnectStatusType::Disabled.into();
        metric
    }

    pub(crate) fn dns_metric(report_time: u64) -> DnsMetric {
        DnsMetric {
            flow_id: 1,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            response_code: "NOERROR".to_string(),
            status: DnsOutcome::Normal,
            report_time,
            duration_ms: 12,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            answers: Vec::new(),
        }
    }

    #[derive(Clone, Default)]
    pub(crate) struct RecordingSink {
        pub connect_batches: Arc<Mutex<Vec<Batch>>>,
        pub dns_batches: Arc<Mutex<Vec<Vec<DnsMetric>>>>,
        pub dns_bucket_batches: Arc<Mutex<Vec<Vec<DnsBucketRow>>>>,
        pub connect_cleanups: Arc<Mutex<u32>>,
        pub dns_cleanups: Arc<Mutex<u32>>,
        pub fail: Arc<AtomicBool>,
    }

    impl RecordingSink {
        pub fn recorded_connect_batches(&self) -> usize {
            self.connect_batches.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl MetricSink for RecordingSink {
        async fn apply_connect_batch(&self, batch: &Batch) -> bool {
            if self.fail.load(Ordering::Relaxed) {
                return false;
            }
            self.connect_batches.lock().unwrap().push(batch.clone());
            true
        }

        async fn apply_dns_batch(&self, metrics: Vec<DnsMetric>) -> bool {
            if self.fail.load(Ordering::Relaxed) {
                return false;
            }
            self.dns_batches.lock().unwrap().push(metrics);
            true
        }

        async fn apply_dns_bucket_rows(&self, rows: Vec<DnsBucketRow>) -> bool {
            if self.fail.load(Ordering::Relaxed) {
                return false;
            }
            self.dns_bucket_batches.lock().unwrap().push(rows);
            true
        }

        async fn cleanup_connect(&self, _config: &MetricRuntimeConfig) {
            *self.connect_cleanups.lock().unwrap() += 1;
        }

        async fn cleanup_dns(&self, _config: &MetricRuntimeConfig) {
            *self.dns_cleanups.lock().unwrap() += 1;
        }

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
        ) -> ConnectHistoryResponse {
            ConnectHistoryResponse::default()
        }

        async fn history_src_ip_stats(
            &self,
            _params: ConnectHistoryQueryParams,
        ) -> Vec<IpHistoryStat> {
            Vec::new()
        }

        async fn history_dst_ip_stats(
            &self,
            _params: ConnectHistoryQueryParams,
        ) -> Vec<IpHistoryStat> {
            Vec::new()
        }

        async fn get_global_stats(
            &self,
            _force_refresh: bool,
        ) -> Result<ConnectGlobalStats, DbError> {
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

        async fn get_dns_summary_parts(
            &self,
            _start_ms: u64,
            _end_ms: u64,
            _flow_id: Option<u32>,
        ) -> DnsSummaryParts {
            DnsSummaryParts::default()
        }
    }

    pub(crate) fn test_caches() -> (FlowCache, IfaceRealtimeCache) {
        (Arc::new(RwLock::new(HashMap::new())), Arc::new(RwLock::new(HashMap::new())))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{RecordingSink, closed_metric, connect_metric, test_caches, test_config};
    use super::*;
    use landscape_common::event::ConnectMessage;
    use std::sync::atomic::Ordering;

    #[test]
    fn queue_stats_accumulate_dropped_and_failed() {
        let stats = WriteQueueStats::default();
        assert_eq!(stats.snapshot(), (0, 0));
        stats.dropped();
        stats.dropped();
        stats.failed();
        assert_eq!(stats.snapshot(), (2, 1));
    }

    #[test]
    fn flush_connect_batch_sends_nothing_when_empty() {
        let (tx, mut rx) = mpsc::channel::<Batch>(4);
        let stats = WriteQueueStats::default();
        let mut pending = Batch::default();
        flush_connect_batch(&tx, &stats, &mut pending);
        assert_eq!(rx.try_recv().unwrap_err(), mpsc::error::TryRecvError::Empty);
        assert_eq!(stats.snapshot().0, 0);
        drop(rx);
    }

    #[test]
    fn flush_connect_batch_sends_pending_and_resets() {
        let (tx, mut rx) = mpsc::channel::<Batch>(4);
        let stats = WriteQueueStats::default();
        let mut pending = Batch::default();
        pending.push_summary(connect_metric(1, 60_000, 100));
        flush_connect_batch(&tx, &stats, &mut pending);
        assert!(pending.is_empty());
        let batch = rx.try_recv().unwrap();
        assert_eq!(batch.op_count(), 1);
        drop(rx);
    }

    #[test]
    fn flush_connect_batch_counts_dropped_when_channel_closed() {
        let (tx, rx) = mpsc::channel::<Batch>(4);
        drop(rx);
        let stats = WriteQueueStats::default();
        let mut pending = Batch::default();
        pending.push_summary(connect_metric(1, 60_000, 100));
        flush_connect_batch(&tx, &stats, &mut pending);
        assert!(pending.is_empty());
        let (dropped, failed) = stats.snapshot();
        assert_eq!(dropped, 1);
        assert_eq!(failed, 0);
    }

    #[tokio::test]
    async fn run_connect_writer_applies_batches_and_counts_failures() {
        let sink = RecordingSink::default();
        let writer_sink: Arc<dyn MetricSink> = Arc::new(sink.clone());
        let (writer_tx, writer_rx) = mpsc::channel::<Batch>(16);
        let stats = WriteQueueStats::default();
        let writer =
            tokio::spawn(run_connect_writer(writer_sink, writer_rx, stats.clone(), test_config()));

        let mut first = Batch::default();
        first.push_summary(connect_metric(1, 60_000, 100));
        writer_tx.send(first).await.unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while sink.recorded_connect_batches() == 0 {
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for apply");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        sink.fail.store(true, Ordering::Relaxed);
        let mut second = Batch::default();
        second.push_summary(connect_metric(2, 60_000, 200));
        writer_tx.send(second).await.unwrap();
        drop(writer_tx);
        tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap();

        assert_eq!(sink.recorded_connect_batches(), 1, "failed batch must not be recorded");
        let (dropped, failed) = stats.snapshot();
        assert_eq!(dropped, 0);
        assert_eq!(failed, 1);
    }

    #[tokio::test]
    async fn connect_writer_runs_cleanup_on_interval() {
        let sink = RecordingSink::default();
        let writer_sink: Arc<dyn MetricSink> = Arc::new(sink.clone());
        let (writer_tx, writer_rx) = mpsc::channel::<Batch>(16);
        let mut config = test_config();
        config.cleanup_interval_secs = 1;
        let writer = tokio::spawn(run_connect_writer(
            writer_sink,
            writer_rx,
            WriteQueueStats::default(),
            config,
        ));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while *sink.connect_cleanups.lock().unwrap() == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for connect cleanup"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(*sink.connect_cleanups.lock().unwrap(), 1, "cleanup fires once per interval");

        drop(writer_tx);
        tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn connect_worker_flushes_batches_at_size_threshold() {
        let (connect_tx, connect_rx) = mpsc::channel(crate::agg::CHANNEL_CAPACITY);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Batch>(16);
        let (flow, iface_realtime) = test_caches();
        let worker = tokio::spawn(run_connect_worker(
            connect_rx,
            writer_tx,
            WriteQueueStats::default(),
            test_config(),
            flow.clone(),
            iface_realtime,
            CancellationToken::new(),
        ));

        // Disabled 状态每条产出 3 bucket + 1 summary = 4 ops ≥ write_batch_size(2),立即 flush。
        connect_tx.send(ConnectMessage::Metric(closed_metric(1, 60_000, 100))).await.unwrap();
        connect_tx.send(ConnectMessage::Metric(closed_metric(2, 60_000, 200))).await.unwrap();
        drop(connect_tx);
        tokio::time::timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();

        let mut batches = Vec::new();
        while let Ok(batch) = writer_rx.try_recv() {
            batches.push(batch);
        }
        assert_eq!(batches.len(), 2, "each metric should flush independently at threshold");
        assert!(batches.iter().all(|batch| batch.op_count() == 4));
    }

    #[tokio::test]
    async fn connect_worker_shutdown_flushes_pending_and_exits() {
        let (connect_tx, connect_rx) = mpsc::channel(crate::agg::CHANNEL_CAPACITY);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Batch>(16);
        let (flow, iface_realtime) = test_caches();
        let shutdown = CancellationToken::new();

        let mut config = test_config();
        config.write_batch_size = 8; // 单条 metric(4 ops)不足以触发阈值 flush,滞留 pending。
        let worker = tokio::spawn(run_connect_worker(
            connect_rx,
            writer_tx,
            WriteQueueStats::default(),
            config,
            flow.clone(),
            iface_realtime,
            shutdown.clone(),
        ));

        connect_tx.send(ConnectMessage::Metric(closed_metric(1, 60_000, 100))).await.unwrap();

        // 等待 worker 消费消息并写入 flow cache,确保 metric 进入 pending 后才触发 shutdown。
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let flow_len = flow.read().expect("metric flow cache poisoned").len();
            if flow_len == 1 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for ingest");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        shutdown.cancel();
        drop(connect_tx);
        tokio::time::timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();

        let batches: Vec<_> = std::iter::from_fn(|| writer_rx.try_recv().ok()).collect();
        assert_eq!(batches.len(), 1, "shutdown must flush the pending batch");
        assert_eq!(batches[0].op_count(), 4);
    }
}
