use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

#[cfg(feature = "metric-persistent")]
use crate::agg::dns_bucket::dns_bucket_rows_from_batch;
use landscape_common::config::MetricRuntimeConfig;
use landscape_common::event::{ConnectMessage, DnsMetricMessage};
#[cfg(feature = "metric-persistent")]
use landscape_common::metric::dns::DnsMetric;
use landscape_core::time::get_current_time_ms;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agg::{
    cleanup_flow_cache, process_connect_metric, second_ring_capacity, second_window_ms, Batch,
    FlowCache, IfaceRealtimeCache,
};
#[cfg(feature = "metric-persistent")]
use crate::agg::{dns_window::DnsRecentWindow, finalize_all_flows};
use crate::sink::MetricSink;

/// 聚合 worker 投递批次给对应 writer 的类型化通道。
/// cleanup 不再走队列,由各 writer 任务内的定时器直接执行。
pub(crate) type ConnectBatchTx = mpsc::Sender<Batch>;

/// DNS writer 通道消息:原始明细行批次。1m 桶行由 writer 从同一批次内构建,
/// 与原始行同批落库(writer 是桶的唯一数据源)。
#[cfg(feature = "metric-persistent")]
#[derive(Debug)]
pub(crate) enum DnsWriteMessage {
    Metrics(Vec<DnsMetric>),
}
#[cfg(feature = "metric-persistent")]
pub(crate) type DnsBatchTx = mpsc::Sender<DnsWriteMessage>;

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

/// DNS 写入 worker:消费原始明细批次,同批聚合出 1m 桶行一并落库
/// (writer 是桶的唯一数据源,桶 = 原始行的忠实分钟聚合),并按 cleanup 周期
/// 执行 dns 清理。与 connect writer 各自独占自己的 sqlite 文件,可并行写,互不阻塞。
#[cfg(feature = "metric-persistent")]
pub(crate) async fn run_dns_writer(
    sink: Arc<dyn MetricSink>,
    mut rx: mpsc::Receiver<DnsWriteMessage>,
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
                sink.cleanup_dns(&config).await;
            }
            msg_opt = rx.recv(), if !closed => {
                match msg_opt {
                    Some(DnsWriteMessage::Metrics(metrics)) => {
                        let rows = dns_bucket_rows_from_batch(&metrics);
                        let raw_ok = sink.apply_dns_batch(metrics).await;
                        let bucket_ok = sink.apply_dns_bucket_rows(rows).await;
                        if !raw_ok || !bucket_ok {
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

#[cfg(feature = "metric-persistent")]
const DNS_BATCH_MAX_ROWS: usize = 500;
/// DNS 落库间隔上限:write_flush_interval_secs 配置更大时,DNS 仍按此值兜底,
/// 避免默认 30s 配置下 DNS 长时间滞留内存。
#[cfg(feature = "metric-persistent")]
const DNS_BATCH_FLUSH_TIMEOUT_SECS: u64 = 15;

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

                let now_ms = get_current_time_ms().unwrap_or_default();
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

    #[cfg(feature = "metric-persistent")]
    {
        let final_batch = finalize_all_flows(&flow_cache, &iface_realtime);
        pending.extend(final_batch);
        flush_connect_batch_on_shutdown(&writer_tx, &queue_stats, &mut pending).await;
    }
}

#[cfg(feature = "metric-persistent")]
fn flush_dns_batch(writer_tx: &DnsBatchTx, stats: &WriteQueueStats, batch: &mut Vec<DnsMetric>) {
    if batch.is_empty() {
        return;
    }
    let metrics = std::mem::take(batch);
    if writer_tx.try_send(DnsWriteMessage::Metrics(metrics)).is_err() {
        stats.dropped();
    }
}

#[cfg(feature = "metric-persistent")]
async fn flush_dns_batch_on_shutdown(
    writer_tx: &DnsBatchTx,
    stats: &WriteQueueStats,
    batch: &mut Vec<DnsMetric>,
) {
    if batch.is_empty() {
        return;
    }
    let metrics = std::mem::take(batch);
    let send_result = tokio::time::timeout(
        Duration::from_secs(5),
        writer_tx.send(DnsWriteMessage::Metrics(metrics)),
    )
    .await;
    if !matches!(send_result, Ok(Ok(()))) {
        stats.dropped();
    }
}

#[cfg(feature = "metric-persistent")]
fn ingest_dns_metric(
    window: &Option<DnsRecentWindow>,
    raw_batch: &mut Vec<DnsMetric>,
    metric: DnsMetric,
) {
    // window 为 None(persistent 初始化失败回退内存)时直接丢弃,不攒批不投递。
    let Some(window) = window else { return };
    let now_ms = get_current_time_ms().unwrap_or_default();
    window.ingest(&metric, now_ms);
    raw_batch.push(metric);
}

/// DNS 聚合 worker:更新 5min 预聚合窗口(聚合层,纯内存) + 攒批投递 dns writer
/// (writer 同批构建 1m 桶落库)。窗口不落库、不与 DB 合并,重启后为空。
/// window 为 None 时仅消费并丢弃(sink 为内存实现时即为丢弃语义)。
#[cfg(feature = "metric-persistent")]
pub(crate) async fn run_dns_worker(
    mut dns_rx: mpsc::Receiver<DnsMetricMessage>,
    writer_tx: DnsBatchTx,
    queue_stats: WriteQueueStats,
    config: MetricRuntimeConfig,
    window: Option<DnsRecentWindow>,
    shutdown: CancellationToken,
) {
    let flush_interval_duration = Duration::from_secs(
        config.write_flush_interval_secs.clamp(1, DNS_BATCH_FLUSH_TIMEOUT_SECS),
    );

    let mut flush_interval = tokio::time::interval(flush_interval_duration);
    flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush_interval.tick().await;

    let mut raw_batch: Vec<DnsMetric> = Vec::new();
    let mut dns_closed = false;

    loop {
        tokio::select! {
            _ = flush_interval.tick() => {
                flush_dns_batch(&writer_tx, &queue_stats, &mut raw_batch);
            }
            _ = shutdown.cancelled() => break,
            msg_opt = dns_rx.recv(), if !dns_closed => {
                match msg_opt {
                    Some(DnsMetricMessage::Metric(metric)) => {
                        ingest_dns_metric(&window, &mut raw_batch, metric);
                        if raw_batch.len() >= DNS_BATCH_MAX_ROWS {
                            flush_dns_batch(&writer_tx, &queue_stats, &mut raw_batch);
                        }
                    }
                    None => dns_closed = true,
                }
            }
        }

        if dns_closed {
            break;
        }
    }

    dns_rx.close();
    // 与 connect worker 相同:shutdown 触发后不等待外部仍持活的 Sender 释放,
    // 立即退出收尾(flush)。
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg_opt = dns_rx.recv() => match msg_opt {
                Some(DnsMetricMessage::Metric(metric)) => {
                    ingest_dns_metric(&window, &mut raw_batch, metric);
                }
                None => break,
            },
        }
    }

    // shutdown 收尾:窗口为纯内存结构,直接丢弃,不落库;仅 flush 剩余原始行批次
    // (1m 桶由 writer 从该批次同批构建)。
    flush_dns_batch_on_shutdown(&writer_tx, &queue_stats, &mut raw_batch).await;
}

/// 无 metric-persistent feature 时的 DNS worker:内存模式下 DNS 指标不聚合、不落库,
/// 仅消费通道,实时/历史查询均由内存 sink 返回空值。
#[cfg(not(feature = "metric-persistent"))]
pub(crate) async fn run_dns_worker(
    mut dns_rx: mpsc::Receiver<DnsMetricMessage>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg = dns_rx.recv() => {
                // 通道关闭(None)时退出,否则会空转自旋。
                if msg.is_none() {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "metric-persistent")]
    use crate::agg::dns_bucket::{DnsBucketRow, DnsSummaryParts};
    use crate::sink::MetricSink;
    use landscape_common::database::error::DbError;
    use landscape_common::metric::connect::{
        ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
        ConnectMetric, ConnectMetricPoint, ConnectStatusType, IpHistoryStat, MetricResolution,
    };
    #[cfg(feature = "metric-persistent")]
    use landscape_common::metric::dns::DnsMetric;
    use landscape_common::metric::dns::{
        DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
        DnsSummaryQueryParams, DnsSummaryResponse,
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, RwLock};

    fn test_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: landscape_common::config::MetricMode::Memory,
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

    fn connect_metric(cpu_id: u32, report_time: u64, ingress_bytes: u64) -> ConnectMetric {
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

    fn closed_metric(cpu_id: u32, report_time: u64, ingress_bytes: u64) -> ConnectMetric {
        let mut metric = connect_metric(cpu_id, report_time, ingress_bytes);
        metric.status = ConnectStatusType::Disabled.into();
        metric
    }

    #[cfg(feature = "metric-persistent")]
    fn dns_metric(report_time: u64) -> DnsMetric {
        DnsMetric {
            flow_id: 1,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            response_code: "NOERROR".to_string(),
            status: landscape_common::metric::dns::DnsOutcome::Normal,
            report_time,
            duration_ms: 12,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            answers: Vec::new(),
        }
    }

    #[derive(Clone, Default)]
    struct RecordingSink {
        connect_batches: Arc<Mutex<Vec<Batch>>>,
        #[cfg(feature = "metric-persistent")]
        dns_batches: Arc<Mutex<Vec<Vec<DnsMetric>>>>,
        #[cfg(feature = "metric-persistent")]
        dns_bucket_batches: Arc<Mutex<Vec<Vec<DnsBucketRow>>>>,
        connect_cleanups: Arc<Mutex<u32>>,
        #[cfg(feature = "metric-persistent")]
        dns_cleanups: Arc<Mutex<u32>>,
        fail: Arc<AtomicBool>,
    }

    impl RecordingSink {
        fn recorded_connect_batches(&self) -> usize {
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

        #[cfg(feature = "metric-persistent")]
        async fn apply_dns_batch(&self, metrics: Vec<DnsMetric>) -> bool {
            if self.fail.load(Ordering::Relaxed) {
                return false;
            }
            self.dns_batches.lock().unwrap().push(metrics);
            true
        }

        #[cfg(feature = "metric-persistent")]
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

        #[cfg(feature = "metric-persistent")]
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

        #[cfg(feature = "metric-persistent")]
        async fn get_dns_summary_parts(
            &self,
            _start_ms: u64,
            _end_ms: u64,
            _flow_id: Option<u32>,
        ) -> DnsSummaryParts {
            DnsSummaryParts::default()
        }
    }

    fn test_caches() -> (FlowCache, IfaceRealtimeCache) {
        (Arc::new(RwLock::new(HashMap::new())), Arc::new(RwLock::new(HashMap::new())))
    }

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

    #[cfg(feature = "metric-persistent")]
    #[tokio::test]
    async fn run_dns_writer_applies_batches_and_counts_failures() {
        let sink = RecordingSink::default();
        let writer_sink: Arc<dyn MetricSink> = Arc::new(sink.clone());
        let (writer_tx, writer_rx) = mpsc::channel::<DnsWriteMessage>(16);
        let stats = WriteQueueStats::default();
        let writer =
            tokio::spawn(run_dns_writer(writer_sink, writer_rx, stats.clone(), test_config()));

        writer_tx.send(DnsWriteMessage::Metrics(vec![dns_metric(60_000)])).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while sink.dns_batches.lock().unwrap().is_empty() {
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for dns apply");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        sink.fail.store(true, Ordering::Relaxed);
        writer_tx.send(DnsWriteMessage::Metrics(vec![dns_metric(61_000)])).await.unwrap();
        drop(writer_tx);
        tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap();

        assert_eq!(sink.dns_batches.lock().unwrap().len(), 1);
        let (dropped, failed) = stats.snapshot();
        assert_eq!(dropped, 0);
        assert_eq!(failed, 1);
    }

    #[cfg(feature = "metric-persistent")]
    #[tokio::test]
    async fn dns_writer_builds_bucket_rows_from_batch() {
        let sink = RecordingSink::default();
        let writer_sink: Arc<dyn MetricSink> = Arc::new(sink.clone());
        let (writer_tx, writer_rx) = mpsc::channel::<DnsWriteMessage>(16);
        let writer = tokio::spawn(run_dns_writer(
            writer_sink,
            writer_rx,
            WriteQueueStats::default(),
            test_config(),
        ));

        // 同一 flow:三个不同分钟(4 条中前两条同分钟)→ 3 个桶行,同分钟合并。
        // base 为分钟对齐时间,避免跨分钟边界的不确定性。
        let base = 100_000_000_000u64 / 60_000 * 60_000;
        let metrics = vec![
            dns_metric(base),
            dns_metric(base + 1_000),
            dns_metric(base - 60_000),
            dns_metric(base - 120_000),
        ];
        writer_tx.send(DnsWriteMessage::Metrics(metrics)).await.unwrap();
        drop(writer_tx);
        tokio::time::timeout(Duration::from_secs(5), writer).await.unwrap().unwrap();

        assert_eq!(sink.dns_batches.lock().unwrap().len(), 1, "raw batch persisted");
        let bucket_batches = sink.dns_bucket_batches.lock().unwrap();
        assert_eq!(bucket_batches.len(), 1, "bucket rows built from the same batch");
        assert_eq!(bucket_batches[0].len(), 3, "three distinct minutes");
        // 行按 (flow_id, bucket_time) 升序,最新分钟(含 2 条)排在最后。
        let row = &bucket_batches[0][2];
        assert_eq!(row.counts.total_queries, 2, "same-minute metrics merged into one row");
        assert_eq!(row.bucket_time, base);
        assert_eq!(row.report_time, base + 1_000, "row carries the batch's last metric time");
        assert_eq!(row.top_domains, vec![("example.com".to_string(), 2)]);
        assert_eq!(row.top_clients, vec![("127.0.0.1".to_string(), 2)]);
        assert_eq!(row.slowest, vec![("example.com".to_string(), 2, 24)]);
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

    #[cfg(feature = "metric-persistent")]
    #[tokio::test]
    async fn dns_worker_flushes_at_max_rows() {
        let (dns_tx, dns_rx) = mpsc::channel(crate::agg::CHANNEL_CAPACITY);
        let (writer_tx, mut writer_rx) = mpsc::channel::<DnsWriteMessage>(16);
        let worker = tokio::spawn(run_dns_worker(
            dns_rx,
            writer_tx,
            WriteQueueStats::default(),
            test_config(),
            Some(crate::agg::dns_window::DnsRecentWindow::new()),
            CancellationToken::new(),
        ));

        for i in 0..DNS_BATCH_MAX_ROWS {
            dns_tx.send(DnsMetricMessage::Metric(dns_metric(60_000 + i as u64))).await.unwrap();
        }
        drop(dns_tx);
        tokio::time::timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();

        let mut dns_batches = Vec::new();
        while let Ok(msg) = writer_rx.try_recv() {
            let DnsWriteMessage::Metrics(metrics) = msg;
            dns_batches.push(metrics.len());
        }
        assert_eq!(dns_batches, vec![DNS_BATCH_MAX_ROWS]);
    }

    #[cfg(feature = "metric-persistent")]
    #[tokio::test]
    async fn dns_worker_window_is_memory_only_on_shutdown() {
        let (dns_tx, dns_rx) = mpsc::channel(crate::agg::CHANNEL_CAPACITY);
        let (writer_tx, mut writer_rx) = mpsc::channel::<DnsWriteMessage>(16);
        let window = crate::agg::dns_window::DnsRecentWindow::new();
        let worker = tokio::spawn(run_dns_worker(
            dns_rx,
            writer_tx,
            WriteQueueStats::default(),
            test_config(),
            Some(window.clone()),
            CancellationToken::new(),
        ));
        let now_ms = get_current_time_ms().unwrap();

        // 窗口内 5 个分钟桶;shutdown 时窗口不落库(纯内存),仅原始行批次投递。
        for offset in 1..=5 {
            let metric = landscape_common::metric::dns::DnsMetric {
                flow_id: 1,
                domain: "example.com".to_string(),
                query_type: "A".to_string(),
                response_code: "NOERROR".to_string(),
                status: landscape_common::metric::dns::DnsOutcome::Normal,
                report_time: now_ms.saturating_sub(offset * 60_000),
                duration_ms: 10,
                src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                answers: Vec::new(),
            };
            dns_tx.send(DnsMetricMessage::Metric(metric)).await.unwrap();
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if window.bucket_count() == 5 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for window fill");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        drop(dns_tx);
        tokio::time::timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();

        let mut raw_metrics = 0usize;
        while let Ok(msg) = writer_rx.try_recv() {
            let DnsWriteMessage::Metrics(metrics) = msg;
            raw_metrics += metrics.len();
        }
        assert_eq!(raw_metrics, 5, "raw rows flushed at shutdown, window itself not persisted");
    }

    #[cfg(not(feature = "metric-persistent"))]
    #[tokio::test]
    async fn dns_worker_discards_metrics_without_persistent() {
        let (dns_tx, dns_rx) = mpsc::channel::<DnsMetricMessage>(8);
        let worker = tokio::spawn(run_dns_worker(dns_rx, CancellationToken::new()));

        let metric = landscape_common::metric::dns::DnsMetric {
            flow_id: 1,
            domain: "example.com".to_string(),
            query_type: "A".to_string(),
            response_code: "NOERROR".to_string(),
            status: landscape_common::metric::dns::DnsOutcome::Normal,
            report_time: 60_000,
            duration_ms: 12,
            src_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            answers: Vec::new(),
        };
        dns_tx.send(DnsMetricMessage::Metric(metric)).await.unwrap();
        drop(dns_tx);
        tokio::time::timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();
    }
}
