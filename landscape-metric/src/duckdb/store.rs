use duckdb::DuckdbConnectionManager;
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
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::cold::ColdStore;
use crate::ingest::{
    cleanup_flow_cache, collect_connect_realtime_snapshot, collect_iface_realtime_snapshot,
    collect_realtime_ip_stats, drain_iface_buckets, finalize_all_flows,
    new_connect_realtime_snapshot, new_iface_realtime_snapshot, process_connect_metric,
    publish_connect_realtime_snapshot, publish_iface_realtime_snapshot, second_points_by_key,
    second_ring_capacity, second_window_ms, BucketWrite, ConnectRealtimeSnapshot, FlowCache,
    IfaceBucketCache, IfaceBucketWrite, IfaceRealtimeCache, IfaceRealtimeSnapshot,
    PersistenceBatch, CHANNEL_CAPACITY, MS_PER_DAY,
};

use super::cold::DuckdbColdStore;
use super::connect::{query as connect_query, schema as connect_schema};
use super::dns::{history as dns_history, schema as dns_schema, summary as dns_summary};
use super::hot_sqlite;

#[derive(Clone)]
pub struct DuckMetricStore {
    connect_tx: mpsc::Sender<ConnectMessage>,
    dns_tx: mpsc::Sender<DnsMetricMessage>,
    shutdown: CancellationToken,
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
/// WAL files above this size are replayed under an elevated memory limit
/// before the pool opens the database with the configured limit.
const WAL_PRECHECKPOINT_THRESHOLD_BYTES: u64 = 1024 * 1024;
/// Minimum memory limit (MB) used while replaying a large WAL. A 16MB WAL
/// (the `wal_autocheckpoint` threshold) can need roughly 500MB to replay, so
/// this must stay comfortably above that even when the configured limit is
/// the 256MB default.
const WAL_REPLAY_MIN_MEMORY_MB: usize = 1024;
/// Replay memory needed per WAL byte. Observed at 20-31x on insert-style WAL
/// replayed against multi-million-row primary key indexes; `wal_autocheckpoint`
/// only bounds the WAL at commit boundaries, and a single large transaction
/// (one `persist_buckets` batch is one transaction) can leave more behind, so
/// the replay budget must scale with the leftover WAL size instead of relying
/// on the floor alone.
const WAL_REPLAY_MEMORY_PER_WAL_BYTE: usize = 32;

#[derive(Debug)]
enum ColdEvent {
    Buckets(Vec<BucketWrite>, Vec<IfaceBucketWrite>),
    Dns(DnsMetric),
}

fn build_duckdb_config_with_memory(
    config: &MetricRuntimeConfig,
    max_memory_mb: usize,
) -> StoreInitResult<duckdb::Config> {
    duckdb::Config::default()
        .threads(config.db_max_threads as i64)
        .map_err(|error| format!("failed to configure duckdb threads: {}", error))?
        .max_memory(&format!("{}MB", max_memory_mb))
        .map_err(|error| format!("failed to configure duckdb max memory: {}", error))
}

fn build_duckdb_config(config: &MetricRuntimeConfig) -> StoreInitResult<duckdb::Config> {
    build_duckdb_config_with_memory(config, config.db_max_memory_mb)
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

fn wal_size_bytes(db_path: &Path) -> u64 {
    std::fs::metadata(metric_db_wal_path(db_path)).map(|metadata| metadata.len()).unwrap_or_else(
        |error| {
            tracing::debug!(
                "failed to stat metric cold wal {}: {}",
                metric_db_wal_path(db_path).display(),
                error,
            );
            0
        },
    )
}

/// Replay a large leftover WAL under an elevated memory limit before the
/// pool opens the database with the configured limit.
///
/// DuckDB replays the WAL while opening the database, and replaying the
/// multi-megabyte WAL left behind by an abnormal shutdown can need several
/// times the configured memory limit (observed on a long-lived production
/// database: a 15.6MB WAL peaked at roughly 490MB during replay). Hitting
/// the limit during replay surfaced as a fatal DuckDB exception that
/// aborted the process instead of an error the recovery ladder could
/// catch, so `systemd` restarted the service, the WAL was still there, and
/// the service crash-looped. Opening once here with a higher limit,
/// checkpointing, and closing again drains the WAL so the configured pool
/// can open cheaply and safely.
fn precheckpoint_large_wal(db_path: &Path, config: &MetricRuntimeConfig) {
    let wal_size = wal_size_bytes(db_path);
    if wal_size <= WAL_PRECHECKPOINT_THRESHOLD_BYTES {
        return;
    }

    let replay_memory_mb = config
        .db_max_memory_mb
        .max(WAL_REPLAY_MIN_MEMORY_MB)
        .max((wal_size as usize * WAL_REPLAY_MEMORY_PER_WAL_BYTE) / (1024 * 1024));
    tracing::warn!(
        "metric cold wal {} is {} bytes (above {} threshold); replaying it under a {}MB memory limit before opening with the configured {}MB limit",
        metric_db_wal_path(db_path).display(),
        wal_size,
        WAL_PRECHECKPOINT_THRESHOLD_BYTES,
        replay_memory_mb,
        config.db_max_memory_mb,
    );

    let result = build_duckdb_config_with_memory(config, replay_memory_mb)
        .and_then(|replay_config| {
            DuckdbConnectionManager::file_with_flags(db_path, replay_config)
                .map_err(|error| format!("failed to open metric duckdb for wal replay: {}", error))
        })
        .and_then(|manager| {
            r2d2::Pool::builder().max_size(1).build(manager).map_err(|error| {
                format!("failed to create metric duckdb wal replay pool: {}", error)
            })
        })
        .and_then(|pool| {
            let conn = pool.get().map_err(|error| {
                format!("failed to get metric duckdb wal replay connection: {}", error)
            })?;
            conn.execute("CHECKPOINT", [])
                .map(|_| ())
                .map_err(|error| format!("failed to checkpoint metric duckdb wal: {}", error))
        });

    match result {
        Ok(()) => tracing::info!(
            "metric cold wal replayed and checkpointed: {} -> {} bytes",
            wal_size,
            wal_size_bytes(db_path),
        ),
        Err(error) => tracing::warn!(
            "failed to precheckpoint metric cold wal at {}: {}; continuing with the normal open path",
            metric_db_wal_path(db_path).display(),
            error,
        ),
    }
}

fn initialize_cold_storage_with_recovery(
    db_path: &Path,
    config: &MetricRuntimeConfig,
) -> StoreInitResult<r2d2::Pool<DuckdbConnectionManager>> {
    precheckpoint_large_wal(db_path, config);
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
    shutdown: CancellationToken,
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
            _ = shutdown.cancelled() => break,
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

fn flush_cold_dns_batch(
    cold_store: &Arc<dyn ColdStore>,
    dns_batch: &mut Vec<DnsMetric>,
    dns_batch_deadline: &mut Option<tokio::time::Instant>,
) -> StoreInitResult<()> {
    *dns_batch_deadline = None;
    if dns_batch.is_empty() {
        return Ok(());
    }
    let metrics = std::mem::take(dns_batch);
    let stats = cold_store.persist_dns(&metrics)?;
    tracing::info!(
        "phase=cold_duckdb.persist dns rows={} elapsed_ms={}",
        stats.rows,
        stats.elapsed_ms
    );
    Ok(())
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
    shutdown: CancellationToken,
) {
    let cleanup_interval_duration = Duration::from_secs(metric_config.cleanup_interval_secs.max(1));
    let mut cleanup_interval = tokio::time::interval(cleanup_interval_duration);
    cleanup_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    cleanup_interval.tick().await;
    let mut cold_pool: Option<r2d2::Pool<DuckdbConnectionManager>> = None;
    let mut dns_batch: Vec<DnsMetric> = Vec::new();
    let mut dns_batch_deadline: Option<tokio::time::Instant> = None;

    loop {
        if shutdown.is_cancelled() {
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
                        _ = shutdown.cancelled() => break,
                    }
                    continue;
                }
            }
        }

        let active_cold: Arc<dyn ColdStore> =
            Arc::new(DuckdbColdStore::new(cold_pool.clone().expect("cold pool set above")));
        tokio::select! {
            _ = cleanup_interval.tick() => {
                if let Err(error) = flush_cold_dns_batch(&active_cold, &mut dns_batch, &mut dns_batch_deadline) {
                    tracing::error!("cold metric dns write failed: {}", error);
                    invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                } else {
                    match active_cold.cleanup(&metric_config) {
                        Ok(stats) => tracing::debug!(
                            "phase=cold_duckdb.cleanup summary deleted_rows={} elapsed_ms={}",
                            stats.deleted_rows,
                            stats.elapsed_ms
                        ),
                        Err(error) => {
                            tracing::error!("cold metric cleanup failed: {}", error);
                            invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                        }
                    }
                }
            }
            msg_opt = cold_rx.recv() => {
                match msg_opt {
                    Some(ColdEvent::Buckets(bucket_writes, iface_bucket_writes)) => {
                        if let Err(error) = flush_cold_dns_batch(&active_cold, &mut dns_batch, &mut dns_batch_deadline) {
                            tracing::error!("cold metric dns write failed: {}", error);
                            invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                        } else {
                            match active_cold.persist_buckets(&bucket_writes, &iface_bucket_writes) {
                                Ok(stats) => tracing::info!(
                                    "phase=cold_duckdb.persist buckets={} iface_buckets={} elapsed_ms={}",
                                    stats.rows,
                                    stats.iface_rows,
                                    stats.elapsed_ms
                                ),
                                Err(error) => {
                                    tracing::error!("cold metric bucket write failed: {}", error);
                                    invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                                }
                            }
                        }
                    }
                    Some(ColdEvent::Dns(metric)) => {
                        if dns_batch.is_empty() {
                            dns_batch_deadline =
                                Some(tokio::time::Instant::now() + Duration::from_secs(DNS_BATCH_FLUSH_TIMEOUT_SECS));
                        }
                        dns_batch.push(metric);
                        if dns_batch.len() >= DNS_BATCH_MAX_ROWS {
                            if let Err(error) = flush_cold_dns_batch(&active_cold, &mut dns_batch, &mut dns_batch_deadline) {
                                tracing::error!("cold metric dns write failed: {}", error);
                                invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                            }
                        }
                    }
                    None => {
                        let _ = flush_cold_dns_batch(&active_cold, &mut dns_batch, &mut dns_batch_deadline);
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(dns_batch_deadline.unwrap_or_else(|| {
                tokio::time::Instant::now() + Duration::from_secs(DNS_BATCH_FLUSH_TIMEOUT_SECS)
            })), if dns_batch_deadline.is_some() => {
                if let Err(error) = flush_cold_dns_batch(&active_cold, &mut dns_batch, &mut dns_batch_deadline) {
                    tracing::error!("cold metric dns write failed: {}", error);
                    invalidate_cold_pool(&cold_pool_cell, &mut cold_pool);
                }
            }
            _ = shutdown.cancelled() => {
                let _ = flush_cold_dns_batch(&active_cold, &mut dns_batch, &mut dns_batch_deadline);
                break;
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
        let shutdown = CancellationToken::new();

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
        let hot_thread_shutdown = shutdown.clone();
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
        let cold_thread_shutdown = shutdown.clone();
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
            shutdown,
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
        self.shutdown.cancel();
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
    use crate::cold::ColdStore;
    use crate::duckdb::cold::DuckdbColdStore;
    use crate::ingest::{BucketKind, PersistenceBatch};
    use duckdb::params;
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
        let cold = DuckdbColdStore::new(pool.clone());
        for chunk in metrics.chunks(DNS_BATCH_MAX_ROWS) {
            cold.persist_dns(chunk).unwrap();
        }

        let conn = pool.get().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM dns_metrics", [], |row| row.get(0)).unwrap();
        assert_eq!(count, metrics.len() as i64);
    }

    #[test]
    fn cold_cleanup_counts_expired_dns_rows() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("dns_cleanup.duckdb");
        let config = test_metric_config();
        let pool = initialize_cold_storage(&db_path, &config).unwrap();
        let now_ms = get_current_time_ms().unwrap();

        let mut expired = test_dns_metric(1);
        expired.report_time = now_ms.saturating_sub((config.dns_retention_days + 1) * MS_PER_DAY);
        let mut retained = test_dns_metric(2);
        retained.report_time = now_ms;

        let cold = DuckdbColdStore::new(pool.clone());
        cold.persist_dns(&[expired, retained]).unwrap();

        let stats = cold.cleanup(&config).unwrap();

        let conn = pool.get().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM dns_metrics", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(stats.deleted_rows, 1);
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

        let cold = DuckdbColdStore::new(pool.clone());
        cold.persist_buckets(&writes, &[]).unwrap();

        let conn = pool.get().unwrap();
        let minute_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1m", [], |row| row.get(0)).unwrap();
        let hour_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1h", [], |row| row.get(0)).unwrap();
        assert_eq!(minute_count, 5);
        assert_eq!(hour_count, 5);
    }

    #[test]
    fn cold_bucket_upsert_batch_merges_conflicting_rows() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("bucket_merge.duckdb");
        let pool = initialize_cold_storage(&db_path, &test_metric_config()).unwrap();
        let cold = DuckdbColdStore::new(pool.clone());

        // Same primary key in one batch: every column must merge exactly like
        // the single-row upsert did (GREATEST per counter, newer
        // create_time_ms decides ifindex).
        let mut older = test_metric(1_000, 1, 60_000, 100, 10, 900, 90);
        older.ifindex = 11;
        older.status = ConnectStatusType::Active;
        older.create_time_ms = 5_000;
        let mut newer = test_metric(1_000, 1, 60_000, 300, 30, 100, 10);
        newer.ifindex = 22;
        newer.status = ConnectStatusType::Disabled;
        newer.create_time_ms = 9_000;
        let batch_one = vec![
            BucketWrite {
                kind: BucketKind::Minute,
                metric: older,
                bucket_report_time: 60_000,
            },
            BucketWrite {
                kind: BucketKind::Minute,
                metric: newer,
                bucket_report_time: 60_000,
            },
        ];
        cold.persist_buckets(&batch_one, &[]).unwrap();

        // A later batch with a stale create_time_ms keeps the newer ifindex.
        let mut stale = test_metric(1_000, 1, 60_000, 50, 5, 50, 5);
        stale.ifindex = 33;
        stale.status = ConnectStatusType::Active;
        stale.create_time_ms = 7_000;
        let batch_two = vec![BucketWrite {
            kind: BucketKind::Minute,
            metric: stale,
            bucket_report_time: 60_000,
        }];
        cold.persist_buckets(&batch_two, &[]).unwrap();

        // An equal create_time_ms takes the later arrival's ifindex, matching
        // the `>=` in the upsert's CASE expression.
        let mut tied = test_metric(1_000, 1, 60_000, 10, 1, 10, 1);
        tied.ifindex = 44;
        tied.status = ConnectStatusType::Unknow;
        tied.create_time_ms = 9_000;
        let batch_three = vec![BucketWrite {
            kind: BucketKind::Minute,
            metric: tied,
            bucket_report_time: 60_000,
        }];
        cold.persist_buckets(&batch_three, &[]).unwrap();

        let conn = pool.get().unwrap();
        let (
            ifindex,
            ingress_bytes,
            ingress_packets,
            egress_bytes,
            egress_packets,
            status,
            create_time_ms,
        ): (i64, i64, i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT ifindex, ingress_bytes, ingress_packets, egress_bytes, egress_packets,
                        status, create_time_ms
                 FROM conn_metrics_1m
                 WHERE create_time = 1000 AND cpu_id = 1 AND report_time = 60000",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(ifindex, 44, "an equal create_time_ms must take the later ifindex");
        assert_eq!(ingress_bytes, 300);
        assert_eq!(ingress_packets, 30);
        assert_eq!(egress_bytes, 900);
        assert_eq!(egress_packets, 90);
        assert_eq!(status, 2, "GREATEST(status) must keep the larger status");
        assert_eq!(create_time_ms, 9_000);
    }

    #[test]
    fn cold_iface_bucket_upsert_accumulates_duplicate_keys() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("iface_merge.duckdb");
        let pool = initialize_cold_storage(&db_path, &test_metric_config()).unwrap();
        let cold = DuckdbColdStore::new(pool.clone());

        // Duplicate (ifindex, report_time) within one batch must fold
        // additively per counter and keep the max active_conns, exactly like
        // the row-by-row upsert did.
        let batch_one = vec![
            IfaceBucketWrite {
                ifindex: 5,
                report_time: 120_000,
                ingress_bytes: 100,
                ingress_packets: 10,
                egress_bytes: 200,
                egress_packets: 20,
                active_conns: 3,
            },
            IfaceBucketWrite {
                ifindex: 5,
                report_time: 120_000,
                ingress_bytes: 200,
                ingress_packets: 20,
                egress_bytes: 50,
                egress_packets: 5,
                active_conns: 7,
            },
        ];
        cold.persist_buckets(&[], &batch_one).unwrap();

        // A later batch keeps accumulating against the stored row.
        let batch_two = vec![IfaceBucketWrite {
            ifindex: 5,
            report_time: 120_000,
            ingress_bytes: 50,
            ingress_packets: 5,
            egress_bytes: 500,
            egress_packets: 50,
            active_conns: 2,
        }];
        cold.persist_buckets(&[], &batch_two).unwrap();

        let conn = pool.get().unwrap();
        let (ingress_bytes, ingress_packets, egress_bytes, egress_packets, active_conns): (
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = conn
            .query_row(
                "SELECT ingress_bytes, ingress_packets, egress_bytes, egress_packets, active_conns
                 FROM iface_metrics_5s
                 WHERE ifindex = 5 AND report_time = 120000",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(ingress_bytes, 350);
        assert_eq!(ingress_packets, 35);
        assert_eq!(egress_bytes, 750);
        assert_eq!(egress_packets, 75);
        assert_eq!(active_conns, 7, "active_conns must keep the max");
    }

    #[test]
    fn cold_bucket_large_interleaved_batch_is_chunked_and_complete() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("bucket_chunks.duckdb");
        let pool = initialize_cold_storage(&db_path, &test_metric_config()).unwrap();

        // More rows than one upsert chunk per table, with the kinds
        // interleaved so grouping by table is exercised on every iteration.
        let kinds = [BucketKind::Minute, BucketKind::Hour, BucketKind::Day];
        let mut remaining = [2500usize, 1300, 700];
        let mut writes: Vec<BucketWrite> = Vec::new();
        let mut next_key: u64 = 20_000;
        loop {
            let mut pushed = false;
            for (kind_slot, remaining_count) in remaining.iter_mut().enumerate() {
                if *remaining_count == 0 {
                    continue;
                }
                *remaining_count -= 1;
                pushed = true;
                let create_time = next_key;
                next_key += 1;
                let report_time = 700_000 + create_time;
                writes.push(BucketWrite {
                    kind: kinds[kind_slot],
                    metric: test_metric(create_time, 0, report_time, 100, 10, 200, 20),
                    bucket_report_time: report_time,
                });
            }
            if !pushed {
                break;
            }
        }
        assert_eq!(writes.len(), 2500 + 1300 + 700);

        let iface_writes: Vec<IfaceBucketWrite> = (0..900)
            .map(|index| IfaceBucketWrite {
                ifindex: (index % 4) as u32 + 1,
                report_time: 800_000 + index as u64,
                ingress_bytes: index as u64,
                ingress_packets: index as u64,
                egress_bytes: index as u64,
                egress_packets: index as u64,
                active_conns: index as u32,
            })
            .collect();

        let cold = DuckdbColdStore::new(pool.clone());
        let stats = cold.persist_buckets(&writes, &iface_writes).unwrap();
        assert_eq!(stats.rows, writes.len());
        assert_eq!(stats.iface_rows, iface_writes.len());

        let conn = pool.get().unwrap();
        let minute_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1m", [], |row| row.get(0)).unwrap();
        let hour_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1h", [], |row| row.get(0)).unwrap();
        let day_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1d", [], |row| row.get(0)).unwrap();
        let iface_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM iface_metrics_5s", [], |row| row.get(0)).unwrap();
        assert_eq!(minute_count, 2500);
        assert_eq!(hour_count, 1300);
        assert_eq!(day_count, 700);
        assert_eq!(iface_count, iface_writes.len() as i64);
    }

    /// Commit `row_count` rows and close the database without checkpointing,
    /// so the committed data is left sitting in a leftover WAL file — the
    /// on-disk state an abnormal shutdown (kill, power loss, abort) leaves
    /// behind.
    fn write_leftover_wal(db_path: &Path, row_count: u64) {
        let writer_manager = DuckdbConnectionManager::file_with_flags(
            db_path,
            build_duckdb_config(&test_metric_config()).unwrap(),
        )
        .unwrap();
        let writer_pool = r2d2::Pool::builder().max_size(1).build(writer_manager).unwrap();
        {
            let conn = writer_pool.get().unwrap();
            connect_schema::create_metrics_table(&conn).unwrap();
            conn.execute("PRAGMA disable_checkpoint_on_shutdown", []).unwrap();
            conn.execute("PRAGMA wal_autocheckpoint='1GB'", []).unwrap();
            // One literal-values insert per statement keeps this helper fast;
            // going through DuckdbColdStore would bind hundreds of thousands
            // of prepared parameters in debug builds.
            for chunk_start in (0..row_count).step_by(5_000) {
                let mut sql = String::from(
                    "INSERT INTO conn_metrics_1m (
                        create_time, cpu_id, report_time, ifindex,
                        ingress_bytes, ingress_packets, egress_bytes, egress_packets,
                        status, create_time_ms
                    ) VALUES ",
                );
                for index in chunk_start..(chunk_start + 5_000).min(row_count) {
                    let create_time = 30_000 + index;
                    sql.push_str(&format!(
                        "({create_time}, 0, {}, 10, 100, 10, 200, 20, 2, {create_time}),",
                        900_000 + create_time,
                    ));
                }
                sql.pop();
                conn.execute_batch(&sql).unwrap();
            }
        }
        drop(writer_pool);
    }

    #[test]
    fn startup_replays_leftover_wal_before_opening_with_configured_memory() {
        init_test_tracing();
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("wal_leftover.duckdb");

        write_leftover_wal(&db_path, 50_000);

        let leftover_wal = wal_size_bytes(&db_path);
        assert!(
            leftover_wal > WAL_PRECHECKPOINT_THRESHOLD_BYTES,
            "expected a leftover wal above {} bytes, got {}",
            WAL_PRECHECKPOINT_THRESHOLD_BYTES,
            leftover_wal,
        );

        // A tighter-than-default limit for the constrained open: with the WAL
        // drained first it must still succeed cheaply.
        let mut config = test_metric_config();
        config.db_max_memory_mb = 64;
        let recovered = initialize_cold_storage_with_recovery(&db_path, &config).unwrap();
        assert!(
            wal_size_bytes(&db_path) < WAL_PRECHECKPOINT_THRESHOLD_BYTES,
            "expected the recovery open to drain the leftover wal, got {} bytes",
            wal_size_bytes(&db_path),
        );

        let conn = recovered.get().unwrap();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM conn_metrics_1m", [], |row| row.get(0)).unwrap();
        assert_eq!(count, 50_000, "wal replay must preserve committed rows");
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
                    crate::ingest::clean_ip_string(&metric.src_ip),
                    answers_json,
                    status_json,
                ],
            )
            .unwrap();
        }
        let single_elapsed = single_start.elapsed();

        let batch_start = Instant::now();
        let cold = DuckdbColdStore::new(batch_pool);
        for chunk in metrics.chunks(DNS_BATCH_MAX_ROWS) {
            cold.persist_dns(chunk).unwrap();
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
