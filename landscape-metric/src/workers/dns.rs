use std::sync::Arc;
use std::time::Duration;

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::event::DnsMetricMessage;
use landscape_common::metric::dns::DnsMetric;
use landscape_common::utils::time::now_ms;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::agg::dns_bucket::dns_bucket_rows_from_batch;
use crate::agg::dns_window::DnsRecentWindow;
use crate::sink::MetricSink;

use super::WriteQueueStats;

/// DNS writer 通道消息:原始明细行批次。1m 桶行由 writer 从同一批次内构建,
/// 与原始行同批落库(writer 是桶的唯一数据源)。
#[derive(Debug)]
pub(crate) enum DnsWriteMessage {
    Metrics(Vec<DnsMetric>),
}
pub(crate) type DnsBatchTx = mpsc::Sender<DnsWriteMessage>;

const DNS_BATCH_MAX_ROWS: usize = 500;
/// DNS 落库间隔上限:write_flush_interval_secs 配置更大时,DNS 仍按此值兜底,
/// 避免默认 30s 配置下 DNS 长时间滞留内存。
const DNS_BATCH_FLUSH_TIMEOUT_SECS: u64 = 15;

/// DNS 写入 worker:消费原始明细批次,同批聚合出 1m 桶行一并落库
/// (writer 是桶的唯一数据源,桶 = 原始行的忠实分钟聚合),并按 cleanup 周期
/// 执行 dns 清理。与 connect writer 各自独占自己的 sqlite 文件,可并行写,互不阻塞。
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

fn flush_dns_batch(
    writer_tx: &Option<DnsBatchTx>,
    stats: &WriteQueueStats,
    batch: &mut Vec<DnsMetric>,
) {
    if batch.is_empty() {
        return;
    }
    let Some(tx) = writer_tx else {
        batch.clear();
        return;
    };
    let metrics = std::mem::take(batch);
    if tx.try_send(DnsWriteMessage::Metrics(metrics)).is_err() {
        stats.dropped();
    }
}

async fn flush_dns_batch_on_shutdown(
    writer_tx: &Option<DnsBatchTx>,
    stats: &WriteQueueStats,
    batch: &mut Vec<DnsMetric>,
) {
    if batch.is_empty() {
        return;
    }
    let Some(tx) = writer_tx else {
        batch.clear();
        return;
    };
    let metrics = std::mem::take(batch);
    let send_result =
        tokio::time::timeout(Duration::from_secs(5), tx.send(DnsWriteMessage::Metrics(metrics)))
            .await;
    if !matches!(send_result, Ok(Ok(()))) {
        stats.dropped();
    }
}

fn ingest_dns_metric(
    window: &Option<DnsRecentWindow>,
    raw_batch: &mut Vec<DnsMetric>,
    metric: DnsMetric,
) {
    // window 为 None(persistent 初始化失败回退内存)时直接丢弃,不攒批不投递。
    let Some(window) = window else { return };
    let now_ms = now_ms();
    window.ingest(&metric, now_ms);
    raw_batch.push(metric);
}

/// DNS 聚合 worker:更新 5min 预聚合窗口(聚合层,纯内存) + 攒批投递 dns writer
/// (writer 同批构建 1m 桶落库)。窗口不落库、不与 DB 合并,重启后为空。
/// window 为 None 时仅消费并丢弃(sink 为内存实现时即为丢弃语义)。
pub(crate) async fn run_dns_worker(
    mut dns_rx: mpsc::Receiver<DnsMetricMessage>,
    writer_tx: Option<DnsBatchTx>,
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

#[cfg(test)]
mod tests {
    use super::super::testing::{RecordingSink, dns_metric, test_config};
    use super::*;
    use landscape_common::event::DnsMetricMessage;
    use std::sync::atomic::Ordering;

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
    async fn dns_worker_flushes_at_max_rows() {
        let (dns_tx, dns_rx) = mpsc::channel(crate::agg::CHANNEL_CAPACITY);
        let (writer_tx, mut writer_rx) = mpsc::channel::<DnsWriteMessage>(16);
        let worker = tokio::spawn(run_dns_worker(
            dns_rx,
            Some(writer_tx),
            WriteQueueStats::default(),
            test_config(),
            Some(DnsRecentWindow::new()),
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

    #[tokio::test]
    async fn dns_worker_window_is_memory_only_on_shutdown() {
        let (dns_tx, dns_rx) = mpsc::channel(crate::agg::CHANNEL_CAPACITY);
        let (writer_tx, mut writer_rx) = mpsc::channel::<DnsWriteMessage>(16);
        let window = DnsRecentWindow::new();
        let worker = tokio::spawn(run_dns_worker(
            dns_rx,
            Some(writer_tx),
            WriteQueueStats::default(),
            test_config(),
            Some(window.clone()),
            CancellationToken::new(),
        ));
        let now_ms = now_ms();

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

    #[tokio::test]
    async fn dns_worker_discards_metrics_without_persistent_link() {
        let (dns_tx, dns_rx) = mpsc::channel::<DnsMetricMessage>(8);
        let worker = tokio::spawn(run_dns_worker(
            dns_rx,
            None,
            WriteQueueStats::default(),
            test_config(),
            None,
            CancellationToken::new(),
        ));

        dns_tx.send(DnsMetricMessage::Metric(dns_metric(60_000))).await.unwrap();
        drop(dns_tx);
        tokio::time::timeout(Duration::from_secs(5), worker).await.unwrap().unwrap();
    }
}
