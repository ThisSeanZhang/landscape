use std::path::Path;

use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectSortKey, IpHistoryStat, SortOrder,
};
use landscape_core::time::get_current_time_ms;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, Transaction};

use crate::ingest::{clean_ip_string, PersistenceBatch};

const GLOBAL_STATS_CACHE_KEY: i64 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SummaryTotals {
    pub total_ingress_bytes: u64,
    pub total_egress_bytes: u64,
    pub total_ingress_pkts: u64,
    pub total_egress_pkts: u64,
}

impl SummaryTotals {
    fn from_metric(metric: &landscape_common::metric::connect::ConnectMetric) -> Self {
        Self {
            total_ingress_bytes: metric.ingress_bytes,
            total_egress_bytes: metric.egress_bytes,
            total_ingress_pkts: metric.ingress_packets,
            total_egress_pkts: metric.egress_packets,
        }
    }

    fn merge_metric(self, metric: &landscape_common::metric::connect::ConnectMetric) -> Self {
        Self {
            total_ingress_bytes: self.total_ingress_bytes.max(metric.ingress_bytes),
            total_egress_bytes: self.total_egress_bytes.max(metric.egress_bytes),
            total_ingress_pkts: self.total_ingress_pkts.max(metric.ingress_packets),
            total_egress_pkts: self.total_egress_pkts.max(metric.egress_packets),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct GlobalStatsDelta {
    total_ingress_bytes: i128,
    total_egress_bytes: i128,
    total_ingress_pkts: i128,
    total_egress_pkts: i128,
    total_connect_count: i128,
}

impl GlobalStatsDelta {
    fn from_summary_change(previous: Option<SummaryTotals>, current: SummaryTotals) -> Self {
        let count_delta = if previous.is_some() { 0 } else { 1 };
        let previous = previous.unwrap_or_default();
        Self {
            total_ingress_bytes: current.total_ingress_bytes as i128
                - previous.total_ingress_bytes as i128,
            total_egress_bytes: current.total_egress_bytes as i128
                - previous.total_egress_bytes as i128,
            total_ingress_pkts: current.total_ingress_pkts as i128
                - previous.total_ingress_pkts as i128,
            total_egress_pkts: current.total_egress_pkts as i128
                - previous.total_egress_pkts as i128,
            total_connect_count: count_delta,
        }
    }

    fn from_removed_stats(stats: &ConnectGlobalStats) -> Self {
        Self {
            total_ingress_bytes: -(stats.total_ingress_bytes as i128),
            total_egress_bytes: -(stats.total_egress_bytes as i128),
            total_ingress_pkts: -(stats.total_ingress_pkts as i128),
            total_egress_pkts: -(stats.total_egress_pkts as i128),
            total_connect_count: -(stats.total_connect_count as i128),
        }
    }

    fn is_zero(&self) -> bool {
        self.total_ingress_bytes == 0
            && self.total_egress_bytes == 0
            && self.total_ingress_pkts == 0
            && self.total_egress_pkts == 0
            && self.total_connect_count == 0
    }
}

fn current_time_ms() -> u64 {
    get_current_time_ms().unwrap_or_default()
}

fn sqlite_url(path: &Path) -> String {
    format!("sqlite://{}?mode=rwc", path.display())
}

pub async fn open_hot_pool(db_path: &Path) -> Result<SqlitePool, String> {
    if let Some(parent) = db_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "failed to create metric sqlite base directory {}: {}",
                    parent.display(),
                    error
                )
            })?;
        }
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .min_connections(1)
        .connect(&sqlite_url(db_path))
        .await
        .map_err(|error| {
            format!("failed to open metric sqlite {}: {}", db_path.display(), error)
        })?;

    for pragma in [
        "PRAGMA journal_mode=WAL",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA busy_timeout=5000",
        "PRAGMA wal_autocheckpoint=4000",
    ] {
        sqlx::query(pragma).execute(&pool).await.map_err(|error| {
            format!("failed to apply metric sqlite pragma `{}`: {}", pragma, error)
        })?;
    }

    initialize_schema(&pool)
        .await
        .map_err(|error| format!("failed to initialize metric sqlite schema: {}", error))?;
    rebuild_global_stats_cache(&pool).await.map_err(|error| {
        format!("failed to initialize metric sqlite global stats cache: {}", error)
    })?;

    Ok(pool)
}

async fn initialize_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conn_summaries (
            create_time INTEGER NOT NULL,
            cpu_id INTEGER NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_port INTEGER NOT NULL,
            l4_proto INTEGER NOT NULL,
            l3_proto INTEGER NOT NULL,
            flow_id INTEGER NOT NULL,
            trace_id INTEGER NOT NULL,
            ifindex INTEGER NOT NULL,
            last_report_time INTEGER NOT NULL,
            total_ingress_bytes INTEGER NOT NULL,
            total_egress_bytes INTEGER NOT NULL,
            total_ingress_pkts INTEGER NOT NULL,
            total_egress_pkts INTEGER NOT NULL,
            status INTEGER NOT NULL,
            create_time_ms INTEGER NOT NULL,
            gress INTEGER NOT NULL,
            PRIMARY KEY (create_time, cpu_id)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_conn_summaries_time ON conn_summaries (last_report_time)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conn_global_stats_cache (
            cache_key INTEGER PRIMARY KEY,
            total_ingress_bytes INTEGER NOT NULL,
            total_egress_bytes INTEGER NOT NULL,
            total_ingress_pkts INTEGER NOT NULL,
            total_egress_pkts INTEGER NOT NULL,
            total_connect_count INTEGER NOT NULL,
            last_calculate_time INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "INSERT INTO conn_global_stats_cache (
            cache_key,
            total_ingress_bytes,
            total_egress_bytes,
            total_ingress_pkts,
            total_egress_pkts,
            total_connect_count,
            last_calculate_time
        ) VALUES (1, 0, 0, 0, 0, 0, 0)
        ON CONFLICT (cache_key) DO NOTHING",
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn query_summary_totals_tx(
    tx: &mut Transaction<'_, Sqlite>,
    key: &ConnectKey,
) -> Result<Option<SummaryTotals>, sqlx::Error> {
    sqlx::query(
        "SELECT total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts
        FROM conn_summaries
        WHERE create_time = ?1 AND cpu_id = ?2",
    )
    .bind(key.create_time as i64)
    .bind(key.cpu_id as i64)
    .fetch_optional(tx.as_mut())
    .await
    .map(|row_opt| {
        row_opt.map(|row| SummaryTotals {
            total_ingress_bytes: row.get::<i64, _>(0).max(0) as u64,
            total_egress_bytes: row.get::<i64, _>(1).max(0) as u64,
            total_ingress_pkts: row.get::<i64, _>(2).max(0) as u64,
            total_egress_pkts: row.get::<i64, _>(3).max(0) as u64,
        })
    })
}

async fn apply_global_stats_cache_delta_tx(
    tx: &mut Transaction<'_, Sqlite>,
    delta: GlobalStatsDelta,
    last_calculate_time: u64,
) -> Result<(), sqlx::Error> {
    if delta.is_zero() {
        return Ok(());
    }

    sqlx::query(
        "UPDATE conn_global_stats_cache
        SET
            total_ingress_bytes = MAX(0, total_ingress_bytes + ?1),
            total_egress_bytes = MAX(0, total_egress_bytes + ?2),
            total_ingress_pkts = MAX(0, total_ingress_pkts + ?3),
            total_egress_pkts = MAX(0, total_egress_pkts + ?4),
            total_connect_count = MAX(0, total_connect_count + ?5),
            last_calculate_time = ?6
        WHERE cache_key = ?7",
    )
    .bind(delta.total_ingress_bytes as i64)
    .bind(delta.total_egress_bytes as i64)
    .bind(delta.total_ingress_pkts as i64)
    .bind(delta.total_egress_pkts as i64)
    .bind(delta.total_connect_count as i64)
    .bind(last_calculate_time as i64)
    .bind(GLOBAL_STATS_CACHE_KEY)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}

async fn upsert_summary_tx(
    tx: &mut Transaction<'_, Sqlite>,
    metric: &landscape_common::metric::connect::ConnectMetric,
) -> Result<(), sqlx::Error> {
    let status: u8 = metric.status.clone().into();
    sqlx::query(
        "INSERT INTO conn_summaries (
            create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto, flow_id, trace_id, ifindex,
            last_report_time, total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts, status, create_time_ms, gress
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
        ON CONFLICT (create_time, cpu_id) DO UPDATE SET
            ifindex = CASE
                WHEN excluded.last_report_time >= conn_summaries.last_report_time THEN excluded.ifindex
                ELSE conn_summaries.ifindex
            END,
            last_report_time = MAX(conn_summaries.last_report_time, excluded.last_report_time),
            total_ingress_bytes = MAX(conn_summaries.total_ingress_bytes, excluded.total_ingress_bytes),
            total_egress_bytes = MAX(conn_summaries.total_egress_bytes, excluded.total_egress_bytes),
            total_ingress_pkts = MAX(conn_summaries.total_ingress_pkts, excluded.total_ingress_pkts),
            total_egress_pkts = MAX(conn_summaries.total_egress_pkts, excluded.total_egress_pkts),
            status = CASE
                WHEN excluded.last_report_time >= conn_summaries.last_report_time THEN excluded.status
                ELSE conn_summaries.status
            END",
    )
    .bind(metric.key.create_time as i64)
    .bind(metric.key.cpu_id as i64)
    .bind(clean_ip_string(&metric.src_ip))
    .bind(clean_ip_string(&metric.dst_ip))
    .bind(metric.src_port as i64)
    .bind(metric.dst_port as i64)
    .bind(metric.l4_proto as i64)
    .bind(metric.l3_proto as i64)
    .bind(metric.flow_id as i64)
    .bind(metric.trace_id as i64)
    .bind(metric.ifindex as i64)
    .bind(metric.report_time as i64)
    .bind(metric.ingress_bytes as i64)
    .bind(metric.egress_bytes as i64)
    .bind(metric.ingress_packets as i64)
    .bind(metric.egress_packets as i64)
    .bind(status as i64)
    .bind(metric.create_time_ms as i64)
    .bind(metric.gress as i64)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}

pub async fn apply_persistence_batch(
    pool: &SqlitePool,
    batch: &PersistenceBatch,
) -> Result<(), sqlx::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    let last_calculate_time = current_time_ms();

    for metric in &batch.summary_metrics {
        let previous_totals = query_summary_totals_tx(&mut tx, &metric.key).await?;
        upsert_summary_tx(&mut tx, metric).await?;
        let merged_totals = previous_totals
            .map(|totals| totals.merge_metric(metric))
            .unwrap_or_else(|| SummaryTotals::from_metric(metric));
        let delta = GlobalStatsDelta::from_summary_change(previous_totals, merged_totals);
        apply_global_stats_cache_delta_tx(&mut tx, delta, last_calculate_time).await?;
    }

    tx.commit().await
}

pub async fn rebuild_global_stats_cache(
    pool: &SqlitePool,
) -> Result<ConnectGlobalStats, sqlx::Error> {
    let row = sqlx::query(
        "SELECT
            COALESCE(SUM(total_ingress_bytes), 0),
            COALESCE(SUM(total_egress_bytes), 0),
            COALESCE(SUM(total_ingress_pkts), 0),
            COALESCE(SUM(total_egress_pkts), 0),
            COUNT(*)
        FROM conn_summaries",
    )
    .fetch_one(pool)
    .await?;

    let stats = ConnectGlobalStats {
        total_ingress_bytes: row.get::<i64, _>(0).max(0) as u64,
        total_egress_bytes: row.get::<i64, _>(1).max(0) as u64,
        total_ingress_pkts: row.get::<i64, _>(2).max(0) as u64,
        total_egress_pkts: row.get::<i64, _>(3).max(0) as u64,
        total_connect_count: row.get::<i64, _>(4).max(0) as u64,
        last_calculate_time: current_time_ms(),
    };

    sqlx::query(
        "INSERT INTO conn_global_stats_cache (
            cache_key,
            total_ingress_bytes,
            total_egress_bytes,
            total_ingress_pkts,
            total_egress_pkts,
            total_connect_count,
            last_calculate_time
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT (cache_key) DO UPDATE SET
            total_ingress_bytes = excluded.total_ingress_bytes,
            total_egress_bytes = excluded.total_egress_bytes,
            total_ingress_pkts = excluded.total_ingress_pkts,
            total_egress_pkts = excluded.total_egress_pkts,
            total_connect_count = excluded.total_connect_count,
            last_calculate_time = excluded.last_calculate_time",
    )
    .bind(GLOBAL_STATS_CACHE_KEY)
    .bind(stats.total_ingress_bytes as i64)
    .bind(stats.total_egress_bytes as i64)
    .bind(stats.total_ingress_pkts as i64)
    .bind(stats.total_egress_pkts as i64)
    .bind(stats.total_connect_count as i64)
    .bind(stats.last_calculate_time as i64)
    .execute(pool)
    .await?;

    Ok(stats)
}

pub async fn query_global_stats(pool: &SqlitePool) -> Result<ConnectGlobalStats, sqlx::Error> {
    let row_opt = sqlx::query(
        "SELECT
            total_ingress_bytes,
            total_egress_bytes,
            total_ingress_pkts,
            total_egress_pkts,
            total_connect_count,
            last_calculate_time
        FROM conn_global_stats_cache
        WHERE cache_key = 1",
    )
    .fetch_optional(pool)
    .await?;

    Ok(row_opt
        .map(|row| ConnectGlobalStats {
            total_ingress_bytes: row.get::<i64, _>(0).max(0) as u64,
            total_egress_bytes: row.get::<i64, _>(1).max(0) as u64,
            total_ingress_pkts: row.get::<i64, _>(2).max(0) as u64,
            total_egress_pkts: row.get::<i64, _>(3).max(0) as u64,
            total_connect_count: row.get::<i64, _>(4).max(0) as u64,
            last_calculate_time: row.get::<i64, _>(5).max(0) as u64,
        })
        .unwrap_or_default())
}

fn parse_ip_or_default(ip: String) -> std::net::IpAddr {
    ip.parse().unwrap_or_else(|_| "0.0.0.0".parse().expect("valid fallback ip"))
}

fn push_connect_common_filters(
    qb: &mut QueryBuilder<'_, Sqlite>,
    params: &ConnectHistoryQueryParams,
    has_where: &mut bool,
) {
    if let Some(start) = params.start_time {
        push_clause(qb, has_where, "last_report_time >= ");
        qb.push_bind(start as i64);
    }
    if let Some(end) = params.end_time {
        push_clause(qb, has_where, "last_report_time <= ");
        qb.push_bind(end as i64);
    }
    if let Some(ip) = params.src_ip.as_ref().filter(|ip| !ip.is_empty()) {
        push_clause(qb, has_where, "src_ip LIKE ");
        qb.push_bind(format!("%{}%", ip));
    }
    if let Some(ip) = params.dst_ip.as_ref().filter(|ip| !ip.is_empty()) {
        push_clause(qb, has_where, "dst_ip LIKE ");
        qb.push_bind(format!("%{}%", ip));
    }
    if let Some(flow_id) = params.flow_id {
        push_clause(qb, has_where, "flow_id = ");
        qb.push_bind(flow_id as i64);
    }
    if let Some(ifindex) = params.ifindex {
        push_clause(qb, has_where, "ifindex = ");
        qb.push_bind(ifindex as i64);
    }
}

fn push_connect_summary_filters(
    qb: &mut QueryBuilder<'_, Sqlite>,
    params: &ConnectHistoryQueryParams,
    has_where: &mut bool,
) {
    if let Some(port) = params.port_start {
        push_clause(qb, has_where, "src_port = ");
        qb.push_bind(port as i64);
    }
    if let Some(port) = params.port_end {
        push_clause(qb, has_where, "dst_port = ");
        qb.push_bind(port as i64);
    }
    if let Some(l3_proto) = params.l3_proto {
        push_clause(qb, has_where, "l3_proto = ");
        qb.push_bind(l3_proto as i64);
    }
    if let Some(l4_proto) = params.l4_proto {
        push_clause(qb, has_where, "l4_proto = ");
        qb.push_bind(l4_proto as i64);
    }
    if let Some(status) = params.status {
        push_clause(qb, has_where, "status = ");
        qb.push_bind(status as i64);
    }
    if let Some(gress) = params.gress {
        push_clause(qb, has_where, "gress = ");
        qb.push_bind(gress as i64);
    }
}

fn push_clause(qb: &mut QueryBuilder<'_, Sqlite>, has_where: &mut bool, prefix: &str) {
    if !*has_where {
        qb.push(" WHERE ");
        *has_where = true;
    } else {
        qb.push(" AND ");
    }
    qb.push(prefix);
}

pub async fn query_historical_summaries_complex(
    pool: &SqlitePool,
    params: ConnectHistoryQueryParams,
) -> Result<Vec<ConnectHistoryStatus>, sqlx::Error> {
    let sort_col = match params.sort_key.clone().unwrap_or_default() {
        ConnectSortKey::Port => "src_port",
        ConnectSortKey::Ingress => "total_ingress_bytes",
        ConnectSortKey::Egress => "total_egress_bytes",
        ConnectSortKey::Time => "last_report_time",
        ConnectSortKey::Duration => "(last_report_time - create_time_ms)",
    };
    let sort_order = match params.sort_order.clone().unwrap_or_default() {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    };

    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT
            create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto, flow_id, trace_id,
            ifindex, total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts, last_report_time, status, create_time_ms, gress
        FROM conn_summaries",
    );
    let mut has_where = false;
    push_connect_common_filters(&mut qb, &params, &mut has_where);
    push_connect_summary_filters(&mut qb, &params, &mut has_where);
    qb.push(" ORDER BY ").push(sort_col).push(" ").push(sort_order);
    if let Some(limit) = params.limit {
        qb.push(format!(" LIMIT {}", limit));
    }

    let rows = qb.build().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| ConnectHistoryStatus {
            key: ConnectKey {
                create_time: row.get::<i64, _>(0) as u64,
                cpu_id: row.get::<i64, _>(1) as u32,
            },
            src_ip: parse_ip_or_default(row.get::<String, _>(2)),
            dst_ip: parse_ip_or_default(row.get::<String, _>(3)),
            src_port: row.get::<i64, _>(4) as u16,
            dst_port: row.get::<i64, _>(5) as u16,
            l4_proto: row.get::<i64, _>(6) as u8,
            l3_proto: row.get::<i64, _>(7) as u8,
            flow_id: row.get::<i64, _>(8) as u8,
            trace_id: row.get::<i64, _>(9) as u8,
            ifindex: row.get::<i64, _>(10).max(0) as u32,
            total_ingress_bytes: row.get::<i64, _>(11).max(0) as u64,
            total_egress_bytes: row.get::<i64, _>(12).max(0) as u64,
            total_ingress_pkts: row.get::<i64, _>(13).max(0) as u64,
            total_egress_pkts: row.get::<i64, _>(14).max(0) as u64,
            last_report_time: row.get::<i64, _>(15).max(0) as u64,
            status: row.get::<i64, _>(16) as u8,
            create_time_ms: row.get::<i64, _>(17).max(0) as u64,
            gress: row.get::<i64, _>(18) as u8,
        })
        .collect())
}

pub async fn query_connection_ip_history(
    pool: &SqlitePool,
    params: ConnectHistoryQueryParams,
    is_src: bool,
) -> Result<Vec<IpHistoryStat>, sqlx::Error> {
    let column = if is_src { "src_ip" } else { "dst_ip" };
    let sort_col = match params.sort_key.clone().unwrap_or(ConnectSortKey::Ingress) {
        ConnectSortKey::Ingress => "total_ingress_bytes",
        ConnectSortKey::Egress => "total_egress_bytes",
        _ => "total_ingress_bytes",
    };
    let sort_order = match params.sort_order.clone().unwrap_or(SortOrder::Desc) {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    };

    let mut qb = QueryBuilder::<Sqlite>::new(&format!(
        "SELECT
            {column},
            SUM(total_ingress_bytes) AS total_ingress_bytes,
            SUM(total_egress_bytes) AS total_egress_bytes,
            SUM(total_ingress_pkts) AS total_ingress_pkts,
            SUM(total_egress_pkts) AS total_egress_pkts,
            COUNT(*) AS connect_count
        FROM conn_summaries"
    ));
    let mut has_where = false;
    push_connect_common_filters(&mut qb, &params, &mut has_where);
    qb.push(" GROUP BY 1 ORDER BY ").push(sort_col).push(" ").push(sort_order);
    qb.push(format!(" LIMIT {}", params.limit.unwrap_or(10)));

    let rows = qb.build().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| IpHistoryStat {
            ip: parse_ip_or_default(row.get::<String, _>(0)),
            flow_id: 0,
            total_ingress_bytes: row.get::<i64, _>(1).max(0) as u64,
            total_egress_bytes: row.get::<i64, _>(2).max(0) as u64,
            total_ingress_pkts: row.get::<i64, _>(3).max(0) as u64,
            total_egress_pkts: row.get::<i64, _>(4).max(0) as u64,
            connect_count: row.get::<i64, _>(5).max(0) as u32,
        })
        .collect())
}

pub async fn cleanup_old_summaries(
    pool: &SqlitePool,
    cutoff_exclusive: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT
            COALESCE(SUM(total_ingress_bytes), 0),
            COALESCE(SUM(total_egress_bytes), 0),
            COALESCE(SUM(total_ingress_pkts), 0),
            COALESCE(SUM(total_egress_pkts), 0),
            COUNT(*)
        FROM conn_summaries
        WHERE last_report_time < ?1",
    )
    .bind(cutoff_exclusive as i64)
    .fetch_one(tx.as_mut())
    .await?;

    let removed = ConnectGlobalStats {
        total_ingress_bytes: row.get::<i64, _>(0).max(0) as u64,
        total_egress_bytes: row.get::<i64, _>(1).max(0) as u64,
        total_ingress_pkts: row.get::<i64, _>(2).max(0) as u64,
        total_egress_pkts: row.get::<i64, _>(3).max(0) as u64,
        total_connect_count: row.get::<i64, _>(4).max(0) as u64,
        last_calculate_time: 0,
    };

    let deleted = sqlx::query("DELETE FROM conn_summaries WHERE last_report_time < ?1")
        .bind(cutoff_exclusive as i64)
        .execute(tx.as_mut())
        .await?
        .rows_affected();

    if deleted > 0 {
        let delta = GlobalStatsDelta::from_removed_stats(&removed);
        apply_global_stats_cache_delta_tx(&mut tx, delta, current_time_ms()).await?;
    }

    tx.commit().await
}
