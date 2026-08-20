use duckdb::{params, params_from_iter, DuckdbConnectionManager};
use landscape_common::concurrency::{spawn_named_thread, task_label, thread_name};
use landscape_common::config::MetricRuntimeConfig;
use landscape_common::event::{ConnectMessage, DnsMetricMessage};
use landscape_common::metric::connect::{
    ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey, ConnectMetricPoint,
    ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat, IpRealtimeStat, MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_core::time::get_current_time_ms;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

use super::connect::{cleanup, query as connect_query, schema as connect_schema};
use super::dns::{history as dns_history, schema as dns_schema, summary as dns_summary};
use super::hot_sqlite;
use super::ingest::{
    cleanup_flow_cache, collect_connect_realtime_snapshot, collect_iface_realtime_snapshot,
    collect_realtime_ip_stats, drain_iface_buckets, finalize_all_flows,
    new_connect_realtime_snapshot, new_iface_realtime_snapshot, process_connect_metric,
    publish_connect_realtime_snapshot, publish_iface_realtime_snapshot, second_points_by_key,
    second_ring_capacity, second_window_ms, BucketWrite, ConnectRealtimeSnapshot, FlowCache,
    IfaceBucketCache, IfaceBucketWrite, IfaceRealtimeCache, IfaceRealtimeSnapshot,
    PersistenceBatch, CHANNEL_CAPACITY, MS_PER_DAY,
};

#[derive(Clone)]
pub struct DuckMetricStore {
    connect_tx: mpsc::Sender<ConnectMessage>,
    dns_tx: mpsc::Sender<DnsMetricMessage>,
    shutdown_tx: watch::Sender<bool>,
    pub config: MetricRuntimeConfig,
    pub(crate) hot_pool: SqlitePool,
    pub(crate) cold_pool: Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
    pub(crate) flow_cache: FlowCache,
    pub(crate) connect_snapshot: ConnectRealtimeSnapshot,
    pub(crate) iface_snapshot: IfaceRealtimeSnapshot,
}

type StoreInitResult<T> = Result<T, String>;

const DUCKDB_POOL_MAX_SIZE: u32 = 8;
const DUCKDB_POOL_MIN_IDLE: u32 = 1;
const COLD_RETRY_DELAY_SECS: u64 = 5;
const DNS_BATCH_MAX_ROWS: usize = 500;
const DNS_BATCH_FLUSH_TIMEOUT_SECS: u64 = 5;
const DNS_METRIC_COLUMNS: usize = 9;

#[derive(Debug)]
enum ColdEvent {
    Buckets(Vec<BucketWrite>, Vec<IfaceBucketWrite>),
    Dns(DnsMetric),
}

fn build_duckdb_config(config: &MetricRuntimeConfig) -> StoreInitResult<duckdb::Config> {
    duckdb::Config::default()
        .threads(config.db_max_threads as i64)
        .map_err(|error| format!("failed to configure duckdb threads: {}", error))?
        .max_memory(&format!("{}MB", config.db_max_memory_mb))
        .map_err(|error| format!("failed to configure duckdb max memory: {}", error))
}

fn metric_db_sidecar_paths(db_path: &Path) -> Vec<PathBuf> {
    let base = db_path.display();
    vec![
        db_path.to_path_buf(),
        PathBuf::from(format!("{base}.wal")),
        PathBuf::from(format!("{base}.tmp")),
    ]
}

fn metric_db_wal_path(db_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.wal", db_path.display()))
}

fn remove_metric_db_files(paths: &[PathBuf]) -> StoreInitResult<Vec<PathBuf>> {
    let mut removed_paths = Vec::new();

    for path in paths {
        if !path.exists() {
            continue;
        }

        std::fs::remove_file(path).map_err(|error| {
            format!("failed to remove metric database file {}: {}", path.display(), error)
        })?;
        removed_paths.push(path.clone());
    }

    Ok(removed_paths)
}

fn remove_metric_db_wal(db_path: &Path) -> StoreInitResult<bool> {
    let wal_path = metric_db_wal_path(db_path);
    if !wal_path.exists() {
        return Ok(false);
    }

    std::fs::remove_file(&wal_path).map_err(|error| {
        format!("failed to remove metric database wal {}: {}", wal_path.display(), error)
    })?;

    Ok(true)
}

fn remove_all_metric_db_artifacts(db_path: &Path) -> StoreInitResult<Vec<PathBuf>> {
    remove_metric_db_files(&metric_db_sidecar_paths(db_path))
}

fn join_display_paths(paths: &[PathBuf]) -> String {
    paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")
}

fn build_cold_pool(
    db_path: &Path,
    config: &MetricRuntimeConfig,
) -> StoreInitResult<r2d2::Pool<DuckdbConnectionManager>> {
    let phase_start = Instant::now();
    let duckdb_config = build_duckdb_config(config)?;
    tracing::info!(
        "metric startup phase=duckdb.cold.build_config db_path={} elapsed_ms={}",
        db_path.display(),
        phase_start.elapsed().as_millis()
    );

    let phase_start = Instant::now();
    let disk_manager =
        DuckdbConnectionManager::file_with_flags(db_path, duckdb_config).map_err(|error| {
            format!("failed to open metric duckdb file {}: {}", db_path.display(), error)
        })?;
    tracing::info!(
        "metric startup phase=duckdb.cold.open_manager db_path={} elapsed_ms={}",
        db_path.display(),
        phase_start.elapsed().as_millis()
    );

    let phase_start = Instant::now();
    let disk_pool = r2d2::Pool::builder()
        .max_size(DUCKDB_POOL_MAX_SIZE)
        .min_idle(Some(DUCKDB_POOL_MIN_IDLE))
        .max_lifetime(Some(Duration::from_secs(120)))
        .build(disk_manager)
        .map_err(|error| format!("failed to create metric duckdb pool: {}", error))?;
    tracing::info!(
        "metric startup phase=duckdb.cold.pool_build_initial_idle db_path={} min_idle={} max_size={} elapsed_ms={}",
        db_path.display(),
        DUCKDB_POOL_MIN_IDLE,
        DUCKDB_POOL_MAX_SIZE,
        phase_start.elapsed().as_millis()
    );

    Ok(disk_pool)
}

fn initialize_cold_storage(
    db_path: &Path,
    config: &MetricRuntimeConfig,
) -> StoreInitResult<r2d2::Pool<DuckdbConnectionManager>> {
    let total_start = Instant::now();

    let phase_start = Instant::now();
    let disk_pool = build_cold_pool(db_path, config)?;
    tracing::info!(
        "metric startup phase=duckdb.cold.build_pool db_path={} elapsed_ms={}",
        db_path.display(),
        phase_start.elapsed().as_millis()
    );

    let phase_start = Instant::now();
    let conn_disk = disk_pool
        .get()
        .map_err(|error| format!("failed to get metric duckdb connection: {}", error))?;
    tracing::info!(
        "metric startup phase=duckdb.cold.acquire_init_connection db_path={} elapsed_ms={}",
        db_path.display(),
        phase_start.elapsed().as_millis()
    );
    let _ = conn_disk.execute("PRAGMA wal_autocheckpoint='16MB'", []);

    let phase_start = Instant::now();
    connect_schema::create_metrics_table(&conn_disk)
        .map_err(|error| format!("failed to create connect metrics tables: {}", error))?;
    tracing::info!(
        "metric startup phase=duckdb.cold.create_metrics_table db_path={} elapsed_ms={}",
        db_path.display(),
        phase_start.elapsed().as_millis()
    );

    let phase_start = Instant::now();
    dns_schema::create_dns_table(&conn_disk)
        .map_err(|error| format!("failed to create dns metrics table: {}", error))?;
    tracing::info!(
        "metric startup phase=duckdb.cold.create_dns_table db_path={} elapsed_ms={}",
        db_path.display(),
        phase_start.elapsed().as_millis()
    );

    tracing::info!(
        "metric startup phase=duckdb.cold.initialize_storage db_path={} elapsed_ms={}",
        db_path.display(),
        total_start.elapsed().as_millis()
    );

    Ok(disk_pool)
}

fn initialize_cold_storage_with_recovery(
    db_path: &Path,
    config: &MetricRuntimeConfig,
) -> StoreInitResult<r2d2::Pool<DuckdbConnectionManager>> {
    match initialize_cold_storage(db_path, config) {
        Ok(result) => Ok(result),
        Err(initial_error) => {
            tracing::warn!(
                "failed to initialize metric duckdb cold store at {}: {}; attempting recovery by deleting the metric wal",
                db_path.display(),
                initial_error
            );

            if remove_metric_db_wal(db_path)? {
                match initialize_cold_storage(db_path, config) {
                    Ok(result) => {
                        tracing::warn!(
                            "metric duckdb cold store recovered after deleting wal {}",
                            metric_db_wal_path(db_path).display()
                        );
                        return Ok(result);
                    }
                    Err(wal_retry_error) => {
                        tracing::warn!(
                            "metric duckdb cold store still failed after deleting wal at {}: {}; removing the metric database and rebuilding",
                            db_path.display(),
                            wal_retry_error
                        );
                    }
                }
            } else {
                tracing::warn!(
                    "metric duckdb cold wal {} was not present; removing the metric database and rebuilding",
                    metric_db_wal_path(db_path).display()
                );
            }

            let removed_paths = remove_all_metric_db_artifacts(db_path)?;
            if removed_paths.is_empty() {
                return Err(initial_error);
            }
            tracing::warn!(
                "removed metric cold database artifacts: {}",
                join_display_paths(&removed_paths)
            );

            initialize_cold_storage(db_path, config).map_err(|retry_error| {
                format!(
                    "failed to recreate metric duckdb cold store after deleting artifacts at {}: {}",
                    db_path.display(),
                    retry_error
                )
            })
        }
    }
}

async fn apply_hot_batch(pool: &SqlitePool, batch: &PersistenceBatch) {
    if batch.is_empty() {
        return;
    }

    if let Err(error) = hot_sqlite::apply_persistence_batch(pool, batch).await {
        tracing::error!("failed to persist hot metric batch to sqlite: {}", error);
    }
}

async fn flush_pending_hot_batch(
    hot_pool: &SqlitePool,
    cold_tx: &mpsc::Sender<ColdEvent>,
    cold_pool_cell: &Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
    pending_batch: &mut PersistenceBatch,
) {
    if pending_batch.is_empty() {
        return;
    }

    let batch = std::mem::take(pending_batch);
    let bucket_writes = batch.bucket_writes.clone();
    let iface_bucket_writes = batch.iface_bucket_writes.clone();
    apply_hot_batch(hot_pool, &batch).await;
    try_enqueue_cold_buckets(cold_tx, cold_pool_cell, bucket_writes, iface_bucket_writes);
}

fn cold_store_ready(
    cold_pool_cell: &Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
) -> bool {
    cold_pool_cell.read().expect("metric cold pool poisoned").is_some()
}

fn try_enqueue_cold_buckets(
    cold_tx: &mpsc::Sender<ColdEvent>,
    cold_pool_cell: &Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
    bucket_writes: Vec<BucketWrite>,
    iface_bucket_writes: Vec<IfaceBucketWrite>,
) {
    if (bucket_writes.is_empty() && iface_bucket_writes.is_empty())
        || !cold_store_ready(cold_pool_cell)
    {
        return;
    }

    if let Err(error) = cold_tx.try_send(ColdEvent::Buckets(bucket_writes, iface_bucket_writes)) {
        tracing::debug!("dropping cold metric bucket batch: {:?}", error);
    }
}

fn try_enqueue_cold_dns(
    cold_tx: &mpsc::Sender<ColdEvent>,
    cold_pool_cell: &Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
    metric: DnsMetric,
) {
    if !cold_store_ready(cold_pool_cell) {
        return;
    }

    if let Err(error) = cold_tx.try_send(ColdEvent::Dns(metric)) {
        tracing::debug!("dropping cold dns metric: {:?}", error);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_hot_thread(
    mut connect_rx: mpsc::Receiver<ConnectMessage>,
    mut dns_rx: mpsc::Receiver<DnsMetricMessage>,
    hot_pool: SqlitePool,
    cold_pool_cell: Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
    cold_tx: mpsc::Sender<ColdEvent>,
    metric_config: MetricRuntimeConfig,
    flow_cache: FlowCache,
    iface_realtime: IfaceRealtimeCache,
    iface_buckets: IfaceBucketCache,
    connect_snapshot: ConnectRealtimeSnapshot,
    iface_snapshot: IfaceRealtimeSnapshot,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let cleanup_interval_duration = Duration::from_secs(metric_config.cleanup_interval_secs.max(1));
    let flush_interval_duration =
        Duration::from_secs(metric_config.write_flush_interval_secs.max(1));
    let write_batch_size = metric_config.write_batch_size.max(1);
    let second_window = second_window_ms(&metric_config);
    let second_ring_cap = second_ring_capacity(&metric_config);

    let mut cleanup_interval = tokio::time::interval(cleanup_interval_duration);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup_interval.tick().await;
    let mut flush_interval = tokio::time::interval(flush_interval_duration);
    flush_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush_interval.tick().await;
    let mut snapshot_interval = tokio::time::interval(Duration::from_secs(1));
    snapshot_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    snapshot_interval.tick().await;

    let mut pending_batch = PersistenceBatch::default();
    let mut connect_closed = false;
    let mut dns_closed = false;

    loop {
        tokio::select! {
            _ = cleanup_interval.tick() => {
                pending_batch.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
                flush_pending_hot_batch(&hot_pool, &cold_tx, &cold_pool_cell, &mut pending_batch).await;

                let now_ms = get_current_time_ms().unwrap_or_default();
                let (flow_stats, batch) = cleanup_flow_cache(&flow_cache, &iface_realtime, now_ms, second_window);
                pending_batch.extend(batch);
                pending_batch.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
                flush_pending_hot_batch(&hot_pool, &cold_tx, &cold_pool_cell, &mut pending_batch).await;
                publish_connect_realtime_snapshot(&flow_cache, &connect_snapshot, now_ms);
                publish_iface_realtime_snapshot(&flow_cache, &iface_snapshot, now_ms);

                let summary_cutoff = now_ms.saturating_sub(metric_config.connect_1d_retention_days * MS_PER_DAY);
                if let Err(error) = hot_sqlite::cleanup_old_summaries(&hot_pool, summary_cutoff).await {
                    tracing::error!("failed to cleanup hot conn_summaries: {}", error);
                }

                tracing::info!(
                    "phase=hot_sqlite.cleanup active_flows={} finalized_flows={} finalized_in_run={} second_ring_points={}",
                    flow_stats.active_flows,
                    flow_stats.finalized_flows,
                    flow_stats.finalized_in_run,
                    flow_stats.second_ring_points,
                );
            }
            _ = flush_interval.tick() => {
                pending_batch.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
                flush_pending_hot_batch(&hot_pool, &cold_tx, &cold_pool_cell, &mut pending_batch).await;
            }
            _ = snapshot_interval.tick() => {
                let now_ms = get_current_time_ms().unwrap_or_default();
                publish_connect_realtime_snapshot(&flow_cache, &connect_snapshot, now_ms);
                publish_iface_realtime_snapshot(&flow_cache, &iface_snapshot, now_ms);
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            msg_opt = connect_rx.recv(), if !connect_closed => {
                match msg_opt {
                    Some(ConnectMessage::Metric(metric)) => {
                        let batch = process_connect_metric(
                            &flow_cache,
                            &iface_realtime,
                            &iface_buckets,
                            metric,
                            second_window,
                            second_ring_cap,
                        );
                        pending_batch.extend(batch);
                        if pending_batch.op_count() >= write_batch_size {
                            pending_batch.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
                            flush_pending_hot_batch(&hot_pool, &cold_tx, &cold_pool_cell, &mut pending_batch).await;
                        }
                    }
                    None => connect_closed = true,
                }
            }
            msg_opt = dns_rx.recv(), if !dns_closed => {
                match msg_opt {
                    Some(DnsMetricMessage::Metric(metric)) => {
                        try_enqueue_cold_dns(&cold_tx, &cold_pool_cell, metric);
                    }
                    None => dns_closed = true,
                }
            }
        }

        if connect_closed && dns_closed {
            break;
        }
    }

    pending_batch.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
    flush_pending_hot_batch(&hot_pool, &cold_tx, &cold_pool_cell, &mut pending_batch).await;

    let final_batch = finalize_all_flows(&flow_cache, &iface_realtime);
    pending_batch.extend(final_batch);
    pending_batch.extend_iface_buckets(drain_iface_buckets(&iface_buckets, &iface_realtime));
    flush_pending_hot_batch(&hot_pool, &cold_tx, &cold_pool_cell, &mut pending_batch).await;
    let now_ms = get_current_time_ms().unwrap_or_default();
    publish_connect_realtime_snapshot(&flow_cache, &connect_snapshot, now_ms);
    publish_iface_realtime_snapshot(&flow_cache, &iface_snapshot, now_ms);
    hot_pool.close().await;
}

fn persist_cold_bucket_writes(
    cold_pool: &r2d2::Pool<DuckdbConnectionManager>,
    bucket_writes: &[BucketWrite],
    iface_bucket_writes: &[IfaceBucketWrite],
) -> StoreInitResult<()> {
    if bucket_writes.is_empty() && iface_bucket_writes.is_empty() {
        return Ok(());
    }

    let conn = cold_pool.get().map_err(|error| {
        format!("failed to get cold duckdb connection for bucket write: {}", error)
    })?;
    let start = Instant::now();

    let tx = conn
        .unchecked_transaction()
        .map_err(|error| format!("failed to begin cold duckdb bucket transaction: {}", error))?;

    if !bucket_writes.is_empty() {
        let mut prepared_table: Option<&str> = None;
        let mut prepared_stmt: Option<duckdb::Statement<'_>> = None;
        for bucket in bucket_writes {
            let table = bucket.kind.table_name();
            if prepared_table != Some(table) {
                prepared_stmt = Some(
                    tx.prepare(&connect_schema::upsert_metric_bucket_values_sql(table)).map_err(
                        |error| {
                            format!("failed to prepare cold bucket upsert for {}: {}", table, error)
                        },
                    )?,
                );
                prepared_table = Some(table);
            }
            let status: u8 = bucket.metric.status.clone().into();
            prepared_stmt
                .as_mut()
                .expect("prepared bucket upsert")
                .execute(params![
                    bucket.metric.key.create_time as i64,
                    bucket.metric.key.cpu_id as i64,
                    bucket.bucket_report_time as i64,
                    bucket.metric.ifindex as i64,
                    bucket.metric.ingress_bytes as i64,
                    bucket.metric.ingress_packets as i64,
                    bucket.metric.egress_bytes as i64,
                    bucket.metric.egress_packets as i64,
                    status as i64,
                    bucket.metric.create_time_ms as i64,
                ])
                .map_err(|error| {
                    format!("failed to write cold bucket row into {}: {}", table, error)
                })?;
        }
        drop(prepared_stmt);
    }

    if !iface_bucket_writes.is_empty() {
        let mut prepared_stmt = tx
            .prepare(&connect_schema::upsert_iface_metric_bucket_values_sql())
            .map_err(|error| format!("failed to prepare cold iface bucket upsert: {}", error))?;
        for bucket in iface_bucket_writes {
            prepared_stmt
                .execute(params![
                    bucket.ifindex as i64,
                    bucket.report_time as i64,
                    bucket.ingress_bytes as i64,
                    bucket.ingress_packets as i64,
                    bucket.egress_bytes as i64,
                    bucket.egress_packets as i64,
                    bucket.active_conns as i64,
                ])
                .map_err(|error| format!("failed to write cold iface bucket row: {}", error))?;
        }
        drop(prepared_stmt);
    }

    tx.commit()
        .map_err(|error| format!("failed to commit cold duckdb bucket transaction: {}", error))?;

    tracing::info!(
        "phase=cold_duckdb.persist buckets={} iface_buckets={} elapsed_ms={}",
        bucket_writes.len(),
        iface_bucket_writes.len(),
        start.elapsed().as_millis()
    );

    Ok(())
}

fn dns_batch_insert_sql(row_count: usize) -> String {
    let values = (0..row_count)
        .map(|index| {
            let base = index * DNS_METRIC_COLUMNS;
            format!(
                "(?{}, ?{}, ?{}, ?{}, ?{}, ?{}, ?{}, ?{}, ?{})",
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO dns_metrics (
            flow_id, domain, query_type, response_code,
            report_time, duration_ms, src_ip, answers, status
        ) VALUES {values}"
    )
}

fn persist_cold_dns_batch(
    cold_pool: &r2d2::Pool<DuckdbConnectionManager>,
    metrics: &[DnsMetric],
) -> StoreInitResult<()> {
    if metrics.is_empty() {
        return Ok(());
    }

    let conn = cold_pool.get().map_err(|error| {
        format!("failed to get cold duckdb connection for dns write: {}", error)
    })?;
    let start = Instant::now();

    let sql = dns_batch_insert_sql(metrics.len());
    let mut values: Vec<Box<dyn duckdb::ToSql>> =
        Vec::with_capacity(metrics.len() * DNS_METRIC_COLUMNS);
    for metric in metrics {
        let answers_json = serde_json::to_string(&metric.answers).unwrap_or_default();
        let status_json = serde_json::to_string(&metric.status).unwrap_or_default();
        values.push(Box::new(metric.flow_id as i64));
        values.push(Box::new(metric.domain.clone()));
        values.push(Box::new(metric.query_type.clone()));
        values.push(Box::new(metric.response_code.clone()));
        values.push(Box::new(metric.report_time as i64));
        values.push(Box::new(metric.duration_ms as i64));
        values.push(Box::new(super::ingest::clean_ip_string(&metric.src_ip)));
        values.push(Box::new(answers_json));
        values.push(Box::new(status_json));
    }

    conn.execute(&sql, params_from_iter(values.iter().map(|value| value.as_ref()))).map_err(
        |error| format!("failed to write cold dns batch of {} rows: {}", metrics.len(), error),
    )?;

    tracing::info!(
        "phase=cold_duckdb.persist dns rows={} elapsed_ms={}",
        metrics.len(),
        start.elapsed().as_millis()
    );

    Ok(())
}

fn cleanup_cold_store(
    cold_pool: &r2d2::Pool<DuckdbConnectionManager>,
    metric_config: &MetricRuntimeConfig,
) -> StoreInitResult<()> {
    let conn = cold_pool
        .get()
        .map_err(|error| format!("failed to get cold duckdb connection for cleanup: {}", error))?;
    let now_ms = get_current_time_ms().unwrap_or_default();
    let cutoff_1m = now_ms.saturating_sub(metric_config.connect_1m_retention_days * MS_PER_DAY);
    let cutoff_1h = now_ms.saturating_sub(metric_config.connect_1h_retention_days * MS_PER_DAY);
    let cutoff_1d = now_ms.saturating_sub(metric_config.connect_1d_retention_days * MS_PER_DAY);
    let cutoff_dns = now_ms.saturating_sub(metric_config.dns_retention_days * MS_PER_DAY);

    dns_schema::cleanup_old_dns_metrics(&conn, cutoff_dns);
    let stats = cleanup::cleanup_old_cold_metrics_only(
        &conn,
        cutoff_1m,
        cutoff_1h,
        cutoff_1d,
        metric_config.cleanup_time_budget_ms,
        metric_config.cleanup_slice_window_secs,
    );
    tracing::info!(
        "phase=cold_duckdb.cleanup elapsed_ms={} budget_hit={} deleted_iface_5s={} deleted_1m={} deleted_1h={} deleted_1d={} deleted_dns_before={}",
        stats.elapsed_ms,
        stats.budget_hit,
        stats.deleted_iface_5s,
        stats.deleted_1m,
        stats.deleted_1h,
        stats.deleted_1d,
        cutoff_dns,
    );

    Ok(())
}

fn flush_cold_dns_batch(
    cold_pool: &r2d2::Pool<DuckdbConnectionManager>,
    dns_batch: &mut Vec<DnsMetric>,
    dns_batch_deadline: &mut Option<tokio::time::Instant>,
) -> StoreInitResult<()> {
    *dns_batch_deadline = None;
    if dns_batch.is_empty() {
        return Ok(());
    }
    let metrics = std::mem::take(dns_batch);
    persist_cold_dns_batch(cold_pool, &metrics)
}

fn invalidate_cold_pool(
    cold_pool_cell: &Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
    cold_pool: &mut Option<r2d2::Pool<DuckdbConnectionManager>>,
) {
    *cold_pool_cell.write().expect("metric cold pool poisoned") = None;
    *cold_pool = None;
}

async fn run_cold_thread(
    mut cold_rx: mpsc::Receiver<ColdEvent>,
    cold_pool_cell: Arc<RwLock<Option<r2d2::Pool<DuckdbConnectionManager>>>>,
    cold_db_path: PathBuf,
    metric_config: MetricRuntimeConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let cleanup_interval_duration = Duration::from_secs(metric_config.cleanup_interval_secs.max(1));
    let mut cleanup_interval = tokio::time::interval(cleanup_interval_duration);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup_interval.tick().await;
    let mut cold_pool: Option<r2d2::Pool<DuckdbConnectionManager>> = None;
    let mut dns_batch: Vec<DnsMetric> = Vec::new();
    let mut dns_batch_deadline: Option<tokio::time::Instant> = None;

    loop {
        if *shutdown_rx.borrow() {
            break;
        }

        if cold_pool.is_none() {
            match initialize_cold_storage_with_recovery(&cold_db_path, &metric_config) {
                Ok(pool) => {
                    tracing::info!("metric cold duckdb ready at {}", cold_db_path.display());
                    *cold_pool_cell.write().expect("metric cold pool poisoned") =
                        Some(pool.clone());
                    cold_pool = Some(pool);
                }
                Err(error) => {
                    tracing::warn!(
                        "failed to initialize metric cold duckdb at {}: {}; retrying in {}s",
                        cold_db_path.display(),
                        error,
                        COLD_RETRY_DELAY_SECS,
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(COLD_RETRY_DELAY_SECS)) => {}
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                break;
                            }
                        }
                    }
                    continue;
                }
            }
        }

        let active_pool = cold_pool.clone().expect("cold pool set above");
        tokio::select! {
            _ = cleanup_interval.tick() => {
                if let Err(error) = flush_cold_dns_batch(&active_pool, &mut dns_batch, &mut dns_batch_deadline) {
                    tracing::error!("cold metric dns write failed: {}", error);
                    invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                } else if let Err(error) = cleanup_cold_store(&active_pool, &metric_config) {
                    tracing::error!("cold metric cleanup failed: {}", error);
                    invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                }
            }
            msg_opt = cold_rx.recv() => {
                match msg_opt {
                    Some(ColdEvent::Buckets(bucket_writes, iface_bucket_writes)) => {
                        if let Err(error) = flush_cold_dns_batch(&active_pool, &mut dns_batch, &mut dns_batch_deadline) {
                            tracing::error!("cold metric dns write failed: {}", error);
                            invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                        } else if let Err(error) = persist_cold_bucket_writes(&active_pool, &bucket_writes, &iface_bucket_writes) {
                            tracing::error!("cold metric bucket write failed: {}", error);
                            invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                        }
                    }
                    Some(ColdEvent::Dns(metric)) => {
                        if dns_batch.is_empty() {
                            dns_batch_deadline =
                                Some(tokio::time::Instant::now() + Duration::from_secs(DNS_BATCH_FLUSH_TIMEOUT_SECS));
                        }
                        dns_batch.push(metric);
                        if dns_batch.len() >= DNS_BATCH_MAX_ROWS {
                            if let Err(error) = flush_cold_dns_batch(&active_pool, &mut dns_batch, &mut dns_batch_deadline) {
                                tracing::error!("cold metric dns write failed: {}", error);
                                invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                            }
                        }
                    }
                    None => {
                        let _ = flush_cold_dns_batch(&active_pool, &mut dns_batch, &mut dns_batch_deadline);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(dns_batch_deadline.unwrap_or_else(|| {
                tokio::time::Instant::now() + Duration::from_secs(DNS_BATCH_FLUSH_TIMEOUT_SECS)
            })), if dns_batch_deadline.is_some() => {
                if let Err(error) = flush_cold_dns_batch(&active_pool, &mut dns_batch, &mut dns_batch_deadline) {
                    tracing::error!("cold metric dns write failed: {}", error);
                    invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    let _ = flush_cold_dns_batch(&active_pool, &mut dns_batch, &mut dns_batch_deadline);
                    break;
                }
            }
        }
    }

    if let Some(pool) =
        cold_pool.or_else(|| cold_pool_cell.read().expect("metric cold pool poisoned").clone())
    {
        if let Ok(conn) = pool.get() {
            if let Err(error) = conn.execute("CHECKPOINT", []) {
                tracing::warn!("failed to checkpoint cold metric duckdb on shutdown: {}", error);
            } else {
                tracing::info!("checkpointed cold metric duckdb on shutdown");
            }
        }
    }
    *cold_pool_cell.write().expect("metric cold pool poisoned") = None;
}

impl DuckMetricStore {
    pub async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Result<Self, String> {
        let total_start = Instant::now();
        if !base_path.exists() {
            std::fs::create_dir_all(&base_path).map_err(|error| {
                format!("failed to create metric base directory {}: {}", base_path.display(), error)
            })?;
        }

        let hot_db_path = base_path
            .join(format!("metrics_v{}.sqlite", landscape_common::LANDSCAPE_METRIC_DB_VERSION));
        let cold_db_path = base_path
            .join(format!("metrics_v{}.duckdb", landscape_common::LANDSCAPE_METRIC_DB_VERSION));

        let (connect_tx, connect_rx) = mpsc::channel::<ConnectMessage>(CHANNEL_CAPACITY);
        let (dns_tx, dns_rx) = mpsc::channel::<DnsMetricMessage>(CHANNEL_CAPACITY);
        let (cold_tx, cold_rx) = mpsc::channel::<ColdEvent>(CHANNEL_CAPACITY);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let phase_start = Instant::now();
        let hot_pool = hot_sqlite::open_hot_pool(&hot_db_path).await?;
        tracing::info!(
            "metric startup phase=hot_sqlite.open db_path={} elapsed_ms={}",
            hot_db_path.display(),
            phase_start.elapsed().as_millis()
        );

        let flow_cache: FlowCache = Arc::new(RwLock::new(HashMap::new()));
        let iface_realtime: IfaceRealtimeCache = Arc::new(RwLock::new(HashMap::new()));
        let iface_buckets: IfaceBucketCache = Arc::new(RwLock::new(HashMap::new()));
        let connect_snapshot = new_connect_realtime_snapshot();
        let iface_snapshot = new_iface_realtime_snapshot();
        let cold_pool = Arc::new(RwLock::new(None));

        let hot_thread_pool = hot_pool.clone();
        let hot_thread_cache = flow_cache.clone();
        let hot_thread_iface_realtime = iface_realtime.clone();
        let hot_thread_iface_buckets = iface_buckets.clone();
        let hot_thread_connect_snapshot = connect_snapshot.clone();
        let hot_thread_iface_snapshot = iface_snapshot.clone();
        let hot_thread_cold_pool = cold_pool.clone();
        let hot_thread_cold_tx = cold_tx;
        let hot_thread_config = config.clone();
        let hot_thread_shutdown = shutdown_rx.clone();
        let phase_start = Instant::now();
        spawn_named_thread(thread_name::fixed::METRIC_DB_WRITER, move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            rt.block_on(run_hot_thread(
                connect_rx,
                dns_rx,
                hot_thread_pool,
                hot_thread_cold_pool,
                hot_thread_cold_tx,
                hot_thread_config,
                hot_thread_cache,
                hot_thread_iface_realtime,
                hot_thread_iface_buckets,
                hot_thread_connect_snapshot,
                hot_thread_iface_snapshot,
                hot_thread_shutdown,
            ));
        })
        .map_err(|error| format!("failed to spawn metric hot writer thread: {}", error))?;
        tracing::info!(
            "metric startup phase=hot_sqlite.spawn_writer db_path={} elapsed_ms={}",
            hot_db_path.display(),
            phase_start.elapsed().as_millis()
        );

        let cold_thread_cell = cold_pool.clone();
        let cold_thread_config = config.clone();
        let cold_thread_shutdown = shutdown_rx.clone();
        let cold_thread_db_path = cold_db_path.clone();
        let phase_start = Instant::now();
        spawn_named_thread(thread_name::fixed::METRIC_DB_COLD, move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            rt.block_on(run_cold_thread(
                cold_rx,
                cold_thread_cell,
                cold_db_path,
                cold_thread_config,
                cold_thread_shutdown,
            ));
        })
        .map_err(|error| format!("failed to spawn metric cold writer thread: {}", error))?;
        tracing::info!(
            "metric startup phase=duckdb.cold.spawn_worker db_path={} elapsed_ms={}",
            cold_thread_db_path.display(),
            phase_start.elapsed().as_millis()
        );

        tracing::info!(
            "metric startup phase=duckdb.new hybrid=sqlite+duckdb hot_db={} elapsed_ms={}",
            hot_db_path.display(),
            total_start.elapsed().as_millis()
        );

        Ok(Self {
            connect_tx,
            dns_tx,
            shutdown_tx,
            config,
            hot_pool,
            cold_pool,
            flow_cache,
            connect_snapshot,
            iface_snapshot,
        })
    }

    pub fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        self.connect_tx.clone()
    }

    pub fn get_dns_msg_channel(&self) -> mpsc::Sender<DnsMetricMessage> {
        self.dns_tx.clone()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        collect_connect_realtime_snapshot(&self.connect_snapshot)
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        collect_iface_realtime_snapshot(&self.iface_snapshot)
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        let now_ms = get_current_time_ms().unwrap_or_default();
        collect_realtime_ip_stats(&self.flow_cache, now_ms, is_src)
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        if resolution == MetricResolution::Second {
            let cutoff = get_current_time_ms()
                .unwrap_or_default()
                .saturating_sub(second_window_ms(&self.config));
            return second_points_by_key(&self.flow_cache, &key, cutoff);
        }

        self.run_cold_query_default(task_label::op::METRIC_QUERY_BY_KEY, move |pool| {
            let Ok(conn) = pool.get() else {
                return Vec::new();
            };
            connect_query::query_metric_by_key(&conn, &key, resolution)
        })
        .await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        match hot_sqlite::query_historical_summaries_complex(&self.hot_pool, params).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query hot sqlite connection summaries: {}", error);
                Vec::new()
            }
        }
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        match hot_sqlite::query_connection_ip_history(&self.hot_pool, params, true).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query hot sqlite src ip stats: {}", error);
                Vec::new()
            }
        }
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        match hot_sqlite::query_connection_ip_history(&self.hot_pool, params, false).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query hot sqlite dst ip stats: {}", error);
                Vec::new()
            }
        }
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        self.run_cold_query_default(task_label::op::METRIC_DNS_HISTORY, move |pool| {
            let Ok(conn) = pool.get() else {
                return DnsHistoryResponse::default();
            };
            dns_history::query_dns_history(&conn, params)
        })
        .await
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        self.run_cold_query_default(task_label::op::METRIC_DNS_SUMMARY, move |pool| {
            let Ok(conn) = pool.get() else {
                return DnsSummaryResponse::default();
            };
            dns_summary::query_dns_summary(&conn, params)
        })
        .await
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        self.run_cold_query_default(task_label::op::METRIC_DNS_LIGHTWEIGHT_SUMMARY, move |pool| {
            let Ok(conn) = pool.get() else {
                return DnsLightweightSummaryResponse::default();
            };
            dns_summary::query_dns_lightweight_summary(&conn, params)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::duckdb::ingest::{BucketKind, PersistenceBatch};
    use landscape_common::config::MetricMode;
    use landscape_common::metric::connect::{ConnectGlobalStats, ConnectMetric, ConnectStatusType};
    use landscape_common::metric::dns::{DnsMetric, DnsOutcome};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Once;
    use tempfile::tempdir;

    fn init_test_tracing() {
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            landscape_common::init_tracing!();
        });
    }

    fn test_dns_metric(index: u32) -> DnsMetric {
        DnsMetric {
            flow_id: index,
            domain: format!("host{}.example.com", index % 100),
            query_type: "A".to_string(),
            response_code: "NOERROR".to_string(),
            status: DnsOutcome::Normal,
            report_time: 1_800_000_000_000 + index as u64 * 1_000,
            duration_ms: index % 50,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, (index % 200) as u8 + 1)),
            answers: vec![format!("1.2.3.{}", (index % 250) + 1)],
        }
    }

    fn test_metric_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: MetricMode::Duckdb,
            connect_second_window_minutes: 1,
            connect_1m_retention_days: 7,
            connect_1h_retention_days: 30,
            connect_1d_retention_days: 90,
            dns_retention_days: 7,
            write_batch_size: 16,
            write_flush_interval_secs: 1,
            db_max_memory_mb: 128,
            db_max_threads: 1,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1_000,
            cleanup_slice_window_secs: 60,
        }
    }

    fn test_metric(
        create_time: u64,
        cpu_id: u32,
        report_time: u64,
        ingress_bytes: u64,
        ingress_packets: u64,
        egress_bytes: u64,
        egress_packets: u64,
    ) -> ConnectMetric {
        ConnectMetric {
            key: ConnectKey { create_time, cpu_id },
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, cpu_id as u8 + 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 1, cpu_id as u8 + 1)),
            src_port: 10_000 + cpu_id as u16,
            dst_port: 20_000 + cpu_id as u16,
            l4_proto: 6,
            l3_proto: 4,
            flow_id: cpu_id as u8,
            trace_id: cpu_id as u8,
            gress: 0,
            ifindex: cpu_id + 10,
            report_time,
            create_time_ms: create_time,
            ingress_bytes,
            ingress_packets,
            egress_bytes,
            egress_packets,
            status: ConnectStatusType::Disabled,
        }
    }

    fn assert_stats_match(actual: &ConnectGlobalStats, expected: &ConnectGlobalStats) {
        assert_eq!(actual.total_ingress_bytes, expected.total_ingress_bytes);
        assert_eq!(actual.total_egress_bytes, expected.total_egress_bytes);
        assert_eq!(actual.total_ingress_pkts, expected.total_ingress_pkts);
        assert_eq!(actual.total_egress_pkts, expected.total_egress_pkts);
        assert_eq!(actual.total_connect_count, expected.total_connect_count);
        assert!(
            actual.last_calculate_time > 0,
            "expected startup rebuild to stamp last_calculate_time, got {:?}",
            actual
        );
    }

    async fn wait_for_global_stats(
        store: &DuckMetricStore,
        predicate: impl Fn(&ConnectGlobalStats) -> bool,
    ) -> ConnectGlobalStats {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let stats = store.get_global_stats(false).await.unwrap();
            if predicate(&stats) {
                return stats;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for global stats update: {:?}",
                stats
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_for_minute_points(
        store: &DuckMetricStore,
        key: ConnectKey,
        expected_len: usize,
    ) -> Vec<ConnectMetricPoint> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let points = store.query_metric_by_key(key.clone(), MetricResolution::Minute).await;
            if points.len() == expected_len {
                return points;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for minute points: {:?}",
                points
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_for_cold_ready(store: &DuckMetricStore) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if store.get_cold_pool().is_some() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for cold duckdb to become ready"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn startup_rebuilds_global_stats_cache_from_existing_summaries() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let base_path = temp_dir.path().to_path_buf();
        let sqlite_path = base_path
            .join(format!("metrics_v{}.sqlite", landscape_common::LANDSCAPE_METRIC_DB_VERSION));
        let hot_pool = hot_sqlite::open_hot_pool(&sqlite_path).await.unwrap();

        let metric_a_initial = test_metric(1_000, 0, 60_000, 100, 10, 200, 20);
        let metric_a_latest = test_metric(1_000, 0, 120_000, 150, 15, 250, 25);
        let metric_b = test_metric(2_000, 1, 180_000, 300, 30, 400, 40);
        let batch = PersistenceBatch {
            summary_metrics: vec![metric_a_initial, metric_a_latest, metric_b],
            bucket_writes: Vec::new(),
            iface_bucket_writes: Vec::new(),
        };
        hot_sqlite::apply_persistence_batch(&hot_pool, &batch).await.unwrap();
        sqlx::query(
            "UPDATE conn_global_stats_cache
             SET total_ingress_bytes = 0,
                 total_egress_bytes = 0,
                 total_ingress_pkts = 0,
                 total_egress_pkts = 0,
                 total_connect_count = 0,
                 last_calculate_time = 0
             WHERE cache_key = 1",
        )
        .execute(&hot_pool)
        .await
        .unwrap();
        hot_pool.close().await;

        let store = DuckMetricStore::new(base_path, test_metric_config()).await.unwrap();
        let stats = store.get_global_stats(false).await.unwrap();
        let expected = ConnectGlobalStats {
            total_ingress_bytes: 450,
            total_egress_bytes: 650,
            total_ingress_pkts: 45,
            total_egress_pkts: 65,
            total_connect_count: 2,
            last_calculate_time: stats.last_calculate_time,
        };
        assert_stats_match(&stats, &expected);

        store.shutdown();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn startup_rebuilds_zero_global_stats_cache_for_empty_database() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let store = DuckMetricStore::new(temp_dir.path().to_path_buf(), test_metric_config())
            .await
            .unwrap();

        let stats = store.get_global_stats(false).await.unwrap();
        let expected = ConnectGlobalStats {
            total_ingress_bytes: 0,
            total_egress_bytes: 0,
            total_ingress_pkts: 0,
            total_egress_pkts: 0,
            total_connect_count: 0,
            last_calculate_time: stats.last_calculate_time,
        };
        assert_stats_match(&stats, &expected);

        store.shutdown();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn startup_incrementally_updates_global_stats_when_new_connection_arrives() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let store = DuckMetricStore::new(temp_dir.path().to_path_buf(), test_metric_config())
            .await
            .unwrap();
        let connect_tx = store.get_connect_msg_channel();

        connect_tx
            .send(ConnectMessage::Metric(test_metric(3_000, 2, 240_000, 100, 10, 150, 15)))
            .await
            .unwrap();
        let stats = wait_for_global_stats(&store, |stats| stats.total_connect_count == 1).await;
        assert_eq!(stats.total_ingress_bytes, 100);
        assert_eq!(stats.total_egress_bytes, 150);
        assert_eq!(stats.total_ingress_pkts, 10);
        assert_eq!(stats.total_egress_pkts, 15);

        connect_tx
            .send(ConnectMessage::Metric(test_metric(3_000, 2, 300_000, 125, 12, 225, 22)))
            .await
            .unwrap();
        let stats = wait_for_global_stats(&store, |stats| {
            stats.total_connect_count == 1
                && stats.total_ingress_bytes == 125
                && stats.total_egress_bytes == 225
        })
        .await;
        assert_eq!(stats.total_ingress_pkts, 12);
        assert_eq!(stats.total_egress_pkts, 22);

        store.shutdown();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[tokio::test]
    async fn cold_store_persists_minute_buckets_after_cold_ready() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let store = DuckMetricStore::new(temp_dir.path().to_path_buf(), test_metric_config())
            .await
            .unwrap();
        let connect_tx = store.get_connect_msg_channel();

        wait_for_cold_ready(&store).await;

        let metric = test_metric(4_000, 3, 360_000, 333, 33, 444, 44);
        let key = metric.key.clone();
        connect_tx.send(ConnectMessage::Metric(metric)).await.unwrap();

        let points = wait_for_minute_points(&store, key, 1).await;
        assert_eq!(points[0].report_time, 360_000);
        assert_eq!(points[0].ingress_bytes, 333);
        assert_eq!(points[0].egress_bytes, 444);
        assert_eq!(points[0].ingress_packets, 33);
        assert_eq!(points[0].egress_packets, 44);

        store.shutdown();
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    #[test]
    fn cold_dns_batch_persists_all_rows() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("dns_batch.duckdb");
        let pool = initialize_cold_storage(&db_path, &test_metric_config()).unwrap();

        let metrics: Vec<DnsMetric> = (0..1200).map(test_dns_metric).collect();
        for chunk in metrics.chunks(DNS_BATCH_MAX_ROWS) {
            persist_cold_dns_batch(&pool, chunk).unwrap();
        }

        let conn = pool.get().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM dns_metrics", [], |row| row.get(0)).unwrap();
        assert_eq!(count, metrics.len() as i64);
    }

    #[test]
    fn cold_bucket_batch_persists_across_tables_in_one_transaction() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("bucket_batch.duckdb");
        let pool = initialize_cold_storage(&db_path, &test_metric_config()).unwrap();

        let writes: Vec<BucketWrite> = (0..10)
            .map(|index| {
                let kind = if index % 2 == 0 { BucketKind::Minute } else { BucketKind::Hour };
                BucketWrite {
                    kind,
                    metric: test_metric(
                        10_000 + index as u64,
                        index % 4,
                        500_000 + index as u64 * 60_000,
                        index as u64 * 100,
                        index as u64,
                        index as u64 * 200,
                        index as u64 * 2,
                    ),
                    bucket_report_time: 500_000 + index as u64 * 60_000,
                }
            })
            .collect();

        persist_cold_bucket_writes(&pool, &writes, &[]).unwrap();

        let conn = pool.get().unwrap();
        let minute_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1m", [], |row| row.get(0)).unwrap();
        let hour_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1h", [], |row| row.get(0)).unwrap();
        assert_eq!(minute_count, 5);
        assert_eq!(hour_count, 5);
    }

    #[test]
    fn cold_dns_batch_write_is_faster_than_single_row_writes() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();

        let single_db = temp_dir.path().join("dns_single.duckdb");
        let single_pool = initialize_cold_storage(&single_db, &test_metric_config()).unwrap();
        let batch_db = temp_dir.path().join("dns_batch_bench.duckdb");
        let batch_pool = initialize_cold_storage(&batch_db, &test_metric_config()).unwrap();

        let metrics: Vec<DnsMetric> = (0..2000).map(test_dns_metric).collect();

        let conn = single_pool.get().unwrap();
        let single_start = Instant::now();
        for metric in &metrics {
            let answers_json = serde_json::to_string(&metric.answers).unwrap();
            let status_json = serde_json::to_string(&metric.status).unwrap();
            conn.execute(
                "INSERT INTO dns_metrics (
                    flow_id, domain, query_type, response_code,
                    report_time, duration_ms, src_ip, answers, status
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    metric.flow_id as i64,
                    metric.domain.clone(),
                    metric.query_type.clone(),
                    metric.response_code.clone(),
                    metric.report_time as i64,
                    metric.duration_ms as i64,
                    super::super::ingest::clean_ip_string(&metric.src_ip),
                    answers_json,
                    status_json,
                ],
            )
            .unwrap();
        }
        let single_elapsed = single_start.elapsed();

        let batch_start = Instant::now();
        for chunk in metrics.chunks(DNS_BATCH_MAX_ROWS) {
            persist_cold_dns_batch(&batch_pool, chunk).unwrap();
        }
        let batch_elapsed = batch_start.elapsed();

        tracing::info!(
            "phase=test.dns_write_bench single_rows={} single_elapsed_ms={} batch_elapsed_ms={}",
            metrics.len(),
            single_elapsed.as_millis(),
            batch_elapsed.as_millis()
        );
        assert!(
            batch_elapsed < single_elapsed,
            "expected batched writes to be faster: single={}ms batch={}ms",
            single_elapsed.as_millis(),
            batch_elapsed.as_millis()
        );
    }
}
