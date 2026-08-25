use std::time::Duration;

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::event::{ConnectMessage, DnsMetricMessage};
use landscape_common::metric::connect::ConnectMetric;
use landscape_common::metric::dns::DnsMetric;
use landscape_core::time::get_current_time_ms;
use sqlx::SqlitePool;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::dns_window::DnsRecentWindow;
use super::sqlite;
use crate::ingest::{
    cleanup_flow_cache, drain_iface_buckets, finalize_all_flows, process_connect_metric,
    second_ring_capacity, second_window_ms, BucketKind, FlowCache, IfaceBucketCache,
    IfaceRealtimeCache, PersistenceBatch, MS_PER_DAY,
};

const DNS_BATCH_MAX_ROWS: usize = 500;
/// DNS 落库间隔上限:write_flush_interval_secs 配置更大时,DNS 仍按此值兜底,
/// 避免默认 30s 配置下 DNS 长时间滞留内存。
const DNS_BATCH_FLUSH_TIMEOUT_SECS: u64 = 5;
/// 全局统计缓存每日漂移校正间隔:超过该时长未重建则后台重建一次。
const GLOBAL_STATS_REBUILD_INTERVAL_SECS: u64 = 24 * 3600;

async fn flush_connect_batch(pool: &SqlitePool, pending: &mut PersistenceBatch) {
    if pending.is_empty() {
        return;
    }
    // 行为决策:写失败直接丢批次、不重试。metric 数据非关键路径,背压/重试会拖垮
    // 采集链路;代价是断电或磁盘异常时会丢少量聚合数据,因此必须保留 error 日志便于排查。
    if let Err(error) = sqlite::connect::apply_connect_batch(pool, pending).await {
        tracing::error!("failed to write persistent connect batch, dropping it: {}", error);
    }
    *pending = PersistenceBatch::default();
}

#[allow(clippy::too_many_arguments)]
async fn handle_connect_metric(
    pool: &SqlitePool,
    pending: &mut PersistenceBatch,
    flow_cache: &FlowCache,
    iface_realtime: &IfaceRealtimeCache,
    iface_buckets: &IfaceBucketCache,
    metric: ConnectMetric,
    second_window: u64,
    second_ring_cap: usize,
    write_batch_size: usize,
) {
    let batch = process_connect_metric(
        flow_cache,
        iface_realtime,
        iface_buckets,
        metric,
        second_window,
        second_ring_cap,
    );
    pending.extend(batch);
    if pending.op_count() >= write_batch_size {
        pending.extend_iface_buckets(drain_iface_buckets(iface_buckets, iface_realtime));
        flush_connect_batch(pool, pending).await;
    }
}

/// Connect 写入 worker:逐条聚合(flow cache 状态机)→ 攒批 → 批量写 connect.db。
pub(crate) async fn run_connect_worker(
    mut connect_rx: mpsc::Receiver<ConnectMessage>,
    pool: SqlitePool,
    config: MetricRuntimeConfig,
    flow_cache: FlowCache,
    iface_realtime: IfaceRealtimeCache,
    iface_buckets: IfaceBucketCache,
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

    let mut pending = PersistenceBatch::default();
    let mut connect_closed = false;
    let mut rebuild_handle: Option<JoinHandle<()>> = None;

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                pending.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
                flush_connect_batch(&pool, &mut pending).await;

                let now_ms = get_current_time_ms().unwrap_or_default();
                let (flow_stats, batch) = cleanup_flow_cache(
                    &flow_cache,
                    &iface_realtime,
                    now_ms,
                    second_window,
                );
                pending.extend(batch);
                pending.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
                flush_connect_batch(&pool, &mut pending).await;

                tracing::info!(
                    "phase=persistent_connect.cleanup active_flows={} finalized_flows={} finalized_in_run={} second_ring_points={}",
                    flow_stats.active_flows,
                    flow_stats.finalized_flows,
                    flow_stats.finalized_in_run,
                    flow_stats.second_ring_points,
                );

                let summary_cutoff =
                    now_ms.saturating_sub(config.connect_1d_retention_days * MS_PER_DAY);
                if let Err(error) = sqlite::connect::cleanup_old_summaries(&pool, summary_cutoff).await {
                    tracing::error!("failed to cleanup persistent conn_summaries: {}", error);
                }

                let cutoffs = [
                    (BucketKind::Minute, now_ms.saturating_sub(config.connect_1m_retention_days * MS_PER_DAY)),
                    (BucketKind::Hour, now_ms.saturating_sub(config.connect_1h_retention_days * MS_PER_DAY)),
                    (BucketKind::Day, now_ms.saturating_sub(config.connect_1d_retention_days * MS_PER_DAY)),
                ];
                let iface_cutoff =
                    now_ms.saturating_sub(config.connect_1m_retention_days * MS_PER_DAY);
                if let Err(error) = sqlite::connect::cleanup_old_buckets(
                    &pool,
                    cutoffs,
                    iface_cutoff,
                    config.cleanup_time_budget_ms,
                    config.cleanup_slice_window_secs,
                ).await {
                    tracing::error!("failed to cleanup persistent connect buckets: {}", error);
                }

                // 每日漂移校正:缓存超过 24h 未重建时,后台异步全量重建(读扫描,
                // WAL 下可与写并发),不阻塞采集链路;同一时刻至多一个重建任务。
                if rebuild_handle.is_none() {
                    match sqlite::connect::global_stats_stale(
                        &pool,
                        GLOBAL_STATS_REBUILD_INTERVAL_SECS,
                    )
                    .await
                    {
                        Ok(true) => {
                            tracing::info!("phase=persistent_connect.global_stats_rebuild starting daily drift correction rebuild");
                            let rebuild_pool = pool.clone();
                            rebuild_handle = Some(tokio::spawn(async move {
                                if let Err(error) =
                                    sqlite::connect::rebuild_global_stats_cache(&rebuild_pool).await
                                {
                                    tracing::error!(
                                        "failed to rebuild persistent connect global stats cache: {}",
                                        error
                                    );
                                }
                            }));
                        }
                        Ok(false) => {}
                        Err(error) => {
                            tracing::error!(
                                "failed to check persistent connect global stats cache staleness: {}",
                                error
                            );
                        }
                    }
                }
            }
            _ = flush_interval.tick() => {
                pending.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
                flush_connect_batch(&pool, &mut pending).await;
            }
            _ = shutdown.cancelled() => break,
            msg_opt = connect_rx.recv(), if !connect_closed => {
                match msg_opt {
                    Some(ConnectMessage::Metric(metric)) => {
                        handle_connect_metric(
                            &pool,
                            &mut pending,
                            &flow_cache,
                            &iface_realtime,
                            &iface_buckets,
                            metric,
                            second_window,
                            second_ring_cap,
                            write_batch_size,
                        )
                        .await;
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
                        &pool,
                        &mut pending,
                        &flow_cache,
                        &iface_realtime,
                        &iface_buckets,
                        metric,
                        second_window,
                        second_ring_cap,
                        write_batch_size,
                    )
                    .await;
                }
                None => break,
            },
        }
    }

    pending.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
    flush_connect_batch(&pool, &mut pending).await;

    let final_batch = finalize_all_flows(&flow_cache, &iface_realtime);
    pending.extend(final_batch);
    pending.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
    flush_connect_batch(&pool, &mut pending).await;

    if let Some(handle) = rebuild_handle.take() {
        let _ = handle.await;
    }
    pool.close().await;
}

async fn flush_dns_batch(pool: &SqlitePool, batch: &mut Vec<DnsMetric>) {
    if batch.is_empty() {
        return;
    }
    let metrics = std::mem::take(batch);
    // 行为决策:同 connect 批次,写失败直接丢弃、不重试,保留 error 日志。
    if let Err(error) = sqlite::dns::insert_dns_batch(pool, &metrics).await {
        tracing::error!("failed to write persistent dns batch, dropping it: {}", error);
    }
}

async fn ingest_dns_metric(
    window: &DnsRecentWindow,
    pool: &SqlitePool,
    batch: &mut Vec<DnsMetric>,
    metric: DnsMetric,
) {
    let now_ms = get_current_time_ms().unwrap_or_default();
    window.ingest(&metric, now_ms);
    batch.push(metric);
    if batch.len() >= DNS_BATCH_MAX_ROWS {
        flush_dns_batch(pool, batch).await;
    }
}

/// DNS 写入 worker:更新 5min 预聚合窗口 + 攒批直写 dns.db。
pub(crate) async fn run_dns_worker(
    mut dns_rx: mpsc::Receiver<DnsMetricMessage>,
    pool: SqlitePool,
    config: MetricRuntimeConfig,
    window: DnsRecentWindow,
    shutdown: CancellationToken,
) {
    let cleanup_interval_duration = Duration::from_secs(config.cleanup_interval_secs.max(1));
    let flush_interval_duration = Duration::from_secs(
        config.write_flush_interval_secs.clamp(1, DNS_BATCH_FLUSH_TIMEOUT_SECS),
    );

    let mut cleanup_interval = tokio::time::interval(cleanup_interval_duration);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup_interval.tick().await;
    let mut flush_interval = tokio::time::interval(flush_interval_duration);
    flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush_interval.tick().await;

    let mut batch: Vec<DnsMetric> = Vec::new();
    let mut dns_closed = false;

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                flush_dns_batch(&pool, &mut batch).await;
                let cutoff = get_current_time_ms()
                    .unwrap_or_default()
                    .saturating_sub(config.dns_retention_days * MS_PER_DAY);
                match sqlite::dns::cleanup_old_dns(&pool, cutoff).await {
                    Ok(deleted) => tracing::debug!(
                        "phase=persistent_dns.cleanup deleted_rows={}",
                        deleted
                    ),
                    Err(error) => tracing::error!("failed to cleanup persistent dns metrics: {}", error),
                }
            }
            _ = flush_interval.tick() => {
                flush_dns_batch(&pool, &mut batch).await;
            }
            _ = shutdown.cancelled() => break,
            msg_opt = dns_rx.recv(), if !dns_closed => {
                match msg_opt {
                    Some(DnsMetricMessage::Metric(metric)) => {
                        ingest_dns_metric(&window, &pool, &mut batch, metric).await;
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
    // 立即退出收尾(flush + close pool)。
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            msg_opt = dns_rx.recv() => match msg_opt {
                Some(DnsMetricMessage::Metric(metric)) => {
                    ingest_dns_metric(&window, &pool, &mut batch, metric).await;
                }
                None => break,
            },
        }
    }

    flush_dns_batch(&pool, &mut batch).await;
    pool.close().await;
}
