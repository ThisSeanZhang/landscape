use std::time::{Duration, Instant};

use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
    ConnectMetricPoint, ConnectSortKey, ConnectStatusType, IpHistoryStat, MetricResolution,
    SortOrder,
};
use landscape_core::time::get_current_time_ms;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, Transaction};

use crate::ingest::{clean_ip_string, BucketKind, BucketWrite, IfaceBucketWrite, PersistenceBatch};

pub(crate) const GLOBAL_STATS_CACHE_KEY: i64 = 1;

/// 历史查询单页条数上限,防止无界 LIMIT 导致慢查询/超大响应。
const MAX_PAGE_SIZE: usize = 200;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SummaryTotals {
    total_ingress_bytes: u64,
    total_egress_bytes: u64,
    total_ingress_pkts: u64,
    total_egress_pkts: u64,
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

    fn is_zero(self) -> bool {
        self.total_ingress_bytes == 0
            && self.total_egress_bytes == 0
            && self.total_ingress_pkts == 0
            && self.total_egress_pkts == 0
            && self.total_connect_count == 0
    }
}

pub(crate) async fn initialize_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    for table in ["conn_metrics_1m", "conn_metrics_1h", "conn_metrics_1d"] {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                create_time INTEGER NOT NULL,
                cpu_id INTEGER NOT NULL,
                report_time INTEGER NOT NULL,
                ifindex INTEGER NOT NULL,
                ingress_bytes INTEGER NOT NULL,
                ingress_packets INTEGER NOT NULL,
                egress_bytes INTEGER NOT NULL,
                egress_packets INTEGER NOT NULL,
                status INTEGER NOT NULL,
                create_time_ms INTEGER NOT NULL,
                PRIMARY KEY (create_time, cpu_id, report_time)
            )"
        ))
        .execute(pool)
        .await?;
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS iface_metrics_5s (
            ifindex INTEGER NOT NULL,
            report_time INTEGER NOT NULL,
            ingress_bytes INTEGER NOT NULL,
            ingress_packets INTEGER NOT NULL,
            egress_bytes INTEGER NOT NULL,
            egress_packets INTEGER NOT NULL,
            active_conns INTEGER NOT NULL,
            PRIMARY KEY (ifindex, report_time)
        )",
    )
    .execute(pool)
    .await?;

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
            cache_key, total_ingress_bytes, total_egress_bytes,
            total_ingress_pkts, total_egress_pkts, total_connect_count, last_calculate_time
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

async fn apply_global_stats_delta_tx(
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

async fn upsert_bucket_tx(
    tx: &mut Transaction<'_, Sqlite>,
    table: &str,
    write: &BucketWrite,
) -> Result<(), sqlx::Error> {
    let status: u8 = write.metric.status.clone().into();
    sqlx::query(&format!(
        "INSERT INTO {table} (
            create_time, cpu_id, report_time, ifindex,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            status, create_time_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ON CONFLICT (create_time, cpu_id, report_time) DO UPDATE SET
            ifindex = CASE
                WHEN excluded.create_time_ms >= {table}.create_time_ms THEN excluded.ifindex
                ELSE {table}.ifindex
            END,
            ingress_bytes = MAX({table}.ingress_bytes, excluded.ingress_bytes),
            ingress_packets = MAX({table}.ingress_packets, excluded.ingress_packets),
            egress_bytes = MAX({table}.egress_bytes, excluded.egress_bytes),
            egress_packets = MAX({table}.egress_packets, excluded.egress_packets),
            status = MAX({table}.status, excluded.status),
            create_time_ms = MAX({table}.create_time_ms, excluded.create_time_ms)"
    ))
    .bind(write.metric.key.create_time as i64)
    .bind(write.metric.key.cpu_id as i64)
    .bind(write.bucket_report_time as i64)
    .bind(write.metric.ifindex as i64)
    .bind(write.metric.ingress_bytes as i64)
    .bind(write.metric.ingress_packets as i64)
    .bind(write.metric.egress_bytes as i64)
    .bind(write.metric.egress_packets as i64)
    .bind(status as i64)
    .bind(write.metric.create_time_ms as i64)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}

async fn upsert_iface_bucket_tx(
    tx: &mut Transaction<'_, Sqlite>,
    write: &IfaceBucketWrite,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO iface_metrics_5s (
            ifindex, report_time,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            active_conns
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT (ifindex, report_time) DO UPDATE SET
            ingress_bytes = iface_metrics_5s.ingress_bytes + excluded.ingress_bytes,
            ingress_packets = iface_metrics_5s.ingress_packets + excluded.ingress_packets,
            egress_bytes = iface_metrics_5s.egress_bytes + excluded.egress_bytes,
            egress_packets = iface_metrics_5s.egress_packets + excluded.egress_packets,
            active_conns = MAX(iface_metrics_5s.active_conns, excluded.active_conns)",
    )
    .bind(write.ifindex as i64)
    .bind(write.report_time as i64)
    .bind(write.ingress_bytes as i64)
    .bind(write.ingress_packets as i64)
    .bind(write.egress_bytes as i64)
    .bind(write.egress_packets as i64)
    .bind(write.active_conns as i64)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}

/// 将一聚合批次(桶 + 连接汇总)以单事务写入 connect.db。
pub(crate) async fn apply_connect_batch(
    pool: &SqlitePool,
    batch: &PersistenceBatch,
) -> Result<(), sqlx::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    let last_calculate_time = get_current_time_ms().unwrap_or_default();

    for metric in &batch.summary_metrics {
        let previous_totals = query_summary_totals_tx(&mut tx, &metric.key).await?;
        upsert_summary_tx(&mut tx, metric).await?;
        let merged_totals = previous_totals
            .map(|totals| totals.merge_metric(metric))
            .unwrap_or_else(|| SummaryTotals::from_metric(metric));
        let delta = GlobalStatsDelta::from_summary_change(previous_totals, merged_totals);
        apply_global_stats_delta_tx(&mut tx, delta, last_calculate_time).await?;
    }

    for kind in [BucketKind::Minute, BucketKind::Hour, BucketKind::Day] {
        for write in batch.bucket_writes.iter().filter(|write| write.kind == kind) {
            upsert_bucket_tx(&mut tx, kind.table_name(), write).await?;
        }
    }

    for write in &batch.iface_bucket_writes {
        upsert_iface_bucket_tx(&mut tx, write).await?;
    }

    tx.commit().await
}

pub(crate) async fn query_metric_by_key(
    pool: &SqlitePool,
    key: &ConnectKey,
    resolution: MetricResolution,
) -> Result<Vec<ConnectMetricPoint>, sqlx::Error> {
    let table = match resolution {
        MetricResolution::Second => return Ok(Vec::new()),
        MetricResolution::Minute => "conn_metrics_1m",
        MetricResolution::Hour => "conn_metrics_1h",
        MetricResolution::Day => "conn_metrics_1d",
    };

    let rows = sqlx::query(&format!(
        "SELECT
            report_time,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            status
        FROM {table}
        WHERE create_time = ?1 AND cpu_id = ?2
        ORDER BY report_time"
    ))
    .bind(key.create_time as i64)
    .bind(key.cpu_id as i64)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ConnectMetricPoint {
            report_time: row.get::<i64, _>(0).max(0) as u64,
            ingress_bytes: row.get::<i64, _>(1).max(0) as u64,
            ingress_packets: row.get::<i64, _>(2).max(0) as u64,
            egress_bytes: row.get::<i64, _>(3).max(0) as u64,
            egress_packets: row.get::<i64, _>(4).max(0) as u64,
            status: ConnectStatusType::from(row.get::<i64, _>(5).max(0) as u8),
        })
        .collect())
}

fn parse_ip_or_default(ip: String) -> std::net::IpAddr {
    ip.parse().unwrap_or_else(|_| "0.0.0.0".parse().expect("valid fallback ip"))
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

pub(crate) async fn query_historical_summaries_complex(
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
    qb.push(format!(" LIMIT {}", params.limit.unwrap_or(MAX_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE)));

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
            status: row.get::<i64, _>(16).max(0) as u8,
            create_time_ms: row.get::<i64, _>(17).max(0) as u64,
            gress: row.get::<i64, _>(18) as u8,
        })
        .collect())
}

pub(crate) async fn query_connection_ip_history(
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
    qb.push(format!(" LIMIT {}", params.limit.unwrap_or(10).clamp(1, MAX_PAGE_SIZE)));

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

pub(crate) async fn rebuild_global_stats_cache(
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
        last_calculate_time: get_current_time_ms().unwrap_or_default(),
    };

    sqlx::query(
        "INSERT INTO conn_global_stats_cache (
            cache_key, total_ingress_bytes, total_egress_bytes,
            total_ingress_pkts, total_egress_pkts, total_connect_count, last_calculate_time
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

pub(crate) async fn query_global_stats(
    pool: &SqlitePool,
) -> Result<ConnectGlobalStats, sqlx::Error> {
    let row_opt = sqlx::query(
        "SELECT
            total_ingress_bytes, total_egress_bytes,
            total_ingress_pkts, total_egress_pkts,
            total_connect_count, last_calculate_time
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

/// 全局统计缓存是否已超过 `stale_after_secs` 未重建(含从未写入的情况)。
pub(crate) async fn global_stats_stale(
    pool: &SqlitePool,
    stale_after_secs: u64,
) -> Result<bool, sqlx::Error> {
    let row_opt =
        sqlx::query("SELECT last_calculate_time FROM conn_global_stats_cache WHERE cache_key = 1")
            .fetch_optional(pool)
            .await?;
    let last_calculate_time = row_opt.map(|row| row.get::<i64, _>(0).max(0) as u64).unwrap_or(0);
    Ok(last_calculate_time == 0
        || get_current_time_ms().unwrap_or_default().saturating_sub(last_calculate_time)
            >= stale_after_secs * 1000)
}

pub(crate) async fn cleanup_old_summaries(
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
        apply_global_stats_delta_tx(&mut tx, delta, get_current_time_ms().unwrap_or_default())
            .await?;
    }

    tx.commit().await
}

/// 按 retention 分片删除过期桶,受 cleanup_time_budget_ms 预算约束。
pub(crate) async fn cleanup_old_buckets(
    pool: &SqlitePool,
    cutoffs: [(BucketKind, u64); 3],
    iface_cutoff: u64,
    cleanup_time_budget_ms: u64,
    cleanup_slice_window_secs: u64,
) -> Result<(), sqlx::Error> {
    let deadline = Instant::now() + Duration::from_millis(cleanup_time_budget_ms.max(1));
    let slice_window_ms = cleanup_slice_window_secs.max(1) * 1000;

    delete_table_in_slices(pool, "iface_metrics_5s", iface_cutoff, slice_window_ms, deadline)
        .await?;

    for (kind, cutoff) in cutoffs {
        if Instant::now() >= deadline {
            break;
        }
        let table = kind.table_name();
        delete_table_in_slices(pool, table, cutoff, slice_window_ms, deadline).await?;
        if Instant::now() >= deadline {
            break;
        }
    }

    Ok(())
}

async fn delete_table_in_slices(
    pool: &SqlitePool,
    table: &str,
    cutoff_exclusive: u64,
    slice_window_ms: u64,
    deadline: Instant,
) -> Result<(), sqlx::Error> {
    let mut cursor: Option<u64> = sqlx::query(&format!(
        "SELECT MIN(report_time) FROM {table} WHERE report_time >= 0 AND report_time < ?1"
    ))
    .bind(cutoff_exclusive as i64)
    .fetch_optional(pool)
    .await?
    .and_then(|row| row.get::<Option<i64>, _>(0))
    .map(|value| value.max(0) as u64);

    while let Some(slice_start) = cursor {
        if Instant::now() >= deadline {
            break;
        }

        let slice_end = slice_start.saturating_add(slice_window_ms).min(cutoff_exclusive);
        sqlx::query(&format!("DELETE FROM {table} WHERE report_time >= ?1 AND report_time < ?2"))
            .bind(slice_start as i64)
            .bind(slice_end as i64)
            .execute(pool)
            .await?;

        cursor = sqlx::query(&format!(
            "SELECT MIN(report_time) FROM {table} WHERE report_time >= ?1 AND report_time < ?2"
        ))
        .bind(slice_end as i64)
        .bind(cutoff_exclusive as i64)
        .fetch_optional(pool)
        .await?
        .and_then(|row| row.get::<Option<i64>, _>(0))
        .map(|value| value.max(0) as u64);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistent::sqlite::open_connect_pool;
    use landscape_common::metric::connect::{ConnectKey, ConnectMetric, ConnectStatusType};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_metric(
        create_time: u64,
        cpu_id: u32,
        report_time: u64,
        ingress_bytes: u64,
        egress_bytes: u64,
        status: ConnectStatusType,
    ) -> ConnectMetric {
        ConnectMetric {
            key: ConnectKey { create_time, cpu_id },
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
            create_time_ms: create_time,
            ingress_bytes,
            ingress_packets: ingress_bytes / 10,
            egress_bytes,
            egress_packets: egress_bytes / 10,
            status,
        }
    }

    async fn test_pool() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open_connect_pool(&dir.path().join("connect.db")).await.unwrap();
        (dir, pool)
    }

    fn batch_with(
        summary: Vec<ConnectMetric>,
        bucket_writes: Vec<BucketWrite>,
        iface_writes: Vec<IfaceBucketWrite>,
    ) -> PersistenceBatch {
        PersistenceBatch {
            summary_metrics: summary,
            bucket_writes,
            iface_bucket_writes: iface_writes,
        }
    }

    #[tokio::test]
    async fn bucket_upsert_uses_greatest_and_iface_accumulates() {
        let (_dir, pool) = test_pool().await;
        let key = ConnectKey { create_time: 1_000, cpu_id: 1 };
        let bucket_time = 60_000u64;

        let first = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Active);
        let mut second = first.clone();
        second.ingress_bytes = 50;
        second.egress_bytes = 400;
        second.create_time_ms = 2_000;

        let mut batch = PersistenceBatch::default();
        batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: first.clone(),
            bucket_report_time: bucket_time,
        });
        batch.iface_bucket_writes.push(IfaceBucketWrite {
            ifindex: 11,
            report_time: bucket_time,
            ingress_bytes: 100,
            ingress_packets: 10,
            egress_bytes: 200,
            egress_packets: 20,
            active_conns: 1,
        });
        apply_connect_batch(&pool, &batch).await.unwrap();

        let mut second_batch = PersistenceBatch::default();
        second_batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: second,
            bucket_report_time: bucket_time,
        });
        second_batch.iface_bucket_writes.push(IfaceBucketWrite {
            ifindex: 11,
            report_time: bucket_time,
            ingress_bytes: 30,
            ingress_packets: 3,
            egress_bytes: 40,
            egress_packets: 4,
            active_conns: 1,
        });
        apply_connect_batch(&pool, &second_batch).await.unwrap();

        let points = query_metric_by_key(&pool, &key, MetricResolution::Minute).await.unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].ingress_bytes, 100, "ingress uses greatest");
        assert_eq!(points[0].egress_bytes, 400, "egress uses greatest");

        let iface_row =
            sqlx::query("SELECT ingress_bytes, egress_bytes, active_conns FROM iface_metrics_5s")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(iface_row.get::<i64, _>(0), 130, "iface accumulates");
        assert_eq!(iface_row.get::<i64, _>(1), 240, "iface accumulates");
        assert_eq!(iface_row.get::<i64, _>(2), 1);
    }

    #[tokio::test]
    async fn summary_upsert_uses_max_and_global_stats_tracks_single_connection() {
        let (_dir, pool) = test_pool().await;
        let key = ConnectKey { create_time: 1_000, cpu_id: 1 };

        let first = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![first.clone()], vec![], vec![])).await.unwrap();

        let second = test_metric(1_000, 1, 70_000, 300, 600, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![second], vec![], vec![])).await.unwrap();

        let stats = query_global_stats(&pool).await.unwrap();
        assert_eq!(stats.total_connect_count, 1, "same key counts once");
        assert_eq!(stats.total_ingress_bytes, 300, "totals use max");
        assert_eq!(stats.total_egress_bytes, 600, "totals use max");

        let history = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams { limit: Some(10), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].key, key);
        assert_eq!(history[0].total_ingress_bytes, 300);
    }

    #[tokio::test]
    async fn distinct_connections_count_independently_in_global_stats() {
        let (_dir, pool) = test_pool().await;

        let a = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        let b = test_metric(1_000, 2, 66_000, 400, 800, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![a, b], vec![], vec![])).await.unwrap();

        let stats = query_global_stats(&pool).await.unwrap();
        assert_eq!(stats.total_connect_count, 2);
        assert_eq!(stats.total_ingress_bytes, 500);
        assert_eq!(stats.total_egress_bytes, 1000);
    }

    #[tokio::test]
    async fn history_query_filters_by_time_and_sorts() {
        let (_dir, pool) = test_pool().await;

        let old = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        let recent = test_metric(1_000, 2, 70_000, 400, 800, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![old, recent], vec![], vec![])).await.unwrap();

        let rows = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams {
                start_time: Some(68_000),
                limit: Some(10),
                sort_key: Some(ConnectSortKey::Ingress),
                sort_order: Some(SortOrder::Desc),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key.cpu_id, 2);

        let ip_rows = query_connection_ip_history(
            &pool,
            ConnectHistoryQueryParams { limit: Some(10), ..Default::default() },
            true,
        )
        .await
        .unwrap();
        assert_eq!(ip_rows.len(), 1);
        assert_eq!(ip_rows[0].total_ingress_bytes, 500);
        assert_eq!(ip_rows[0].connect_count, 2);
    }

    #[tokio::test]
    async fn cleanup_old_summaries_decrements_global_stats() {
        let (_dir, pool) = test_pool().await;

        let old = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        let recent = test_metric(1_000, 2, 70_000, 400, 800, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![old, recent], vec![], vec![])).await.unwrap();

        cleanup_old_summaries(&pool, 68_000).await.unwrap();

        let stats = query_global_stats(&pool).await.unwrap();
        assert_eq!(stats.total_connect_count, 1);
        assert_eq!(stats.total_ingress_bytes, 400);

        let rows = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams { limit: Some(10), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key.cpu_id, 2);
    }

    #[tokio::test]
    async fn cleanup_old_buckets_deletes_expired_slices() {
        let (_dir, pool) = test_pool().await;

        let expired = test_metric(1_000, 1, 55_000, 100, 200, ConnectStatusType::Active);
        let kept = test_metric(1_000, 2, 95_000, 100, 200, ConnectStatusType::Active);
        let mut batch = PersistenceBatch::default();
        batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: expired,
            bucket_report_time: 55_000,
        });
        batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: kept,
            bucket_report_time: 95_000,
        });
        apply_connect_batch(&pool, &batch).await.unwrap();

        cleanup_old_buckets(
            &pool,
            [(BucketKind::Minute, 60_000), (BucketKind::Hour, 60_000), (BucketKind::Day, 60_000)],
            60_000,
            1_000,
            60,
        )
        .await
        .unwrap();

        let points = query_metric_by_key(
            &pool,
            &ConnectKey { create_time: 1_000, cpu_id: 1 },
            MetricResolution::Minute,
        )
        .await
        .unwrap();
        assert!(points.is_empty(), "expired bucket deleted");

        let kept_points = query_metric_by_key(
            &pool,
            &ConnectKey { create_time: 1_000, cpu_id: 2 },
            MetricResolution::Minute,
        )
        .await
        .unwrap();
        assert_eq!(kept_points.len(), 1, "retained bucket survives");
    }

    #[tokio::test]
    async fn cleanup_old_buckets_deletes_expired_iface_5s_rows() {
        let (_dir, pool) = test_pool().await;

        let mut batch = PersistenceBatch::default();
        batch.iface_bucket_writes.push(IfaceBucketWrite {
            ifindex: 11,
            report_time: 55_000,
            ingress_bytes: 100,
            ingress_packets: 10,
            egress_bytes: 200,
            egress_packets: 20,
            active_conns: 3,
        });
        batch.iface_bucket_writes.push(IfaceBucketWrite {
            ifindex: 12,
            report_time: 95_000,
            ingress_bytes: 100,
            ingress_packets: 10,
            egress_bytes: 200,
            egress_packets: 20,
            active_conns: 3,
        });
        apply_connect_batch(&pool, &batch).await.unwrap();

        cleanup_old_buckets(
            &pool,
            [(BucketKind::Minute, 60_000), (BucketKind::Hour, 60_000), (BucketKind::Day, 60_000)],
            60_000,
            1_000,
            60,
        )
        .await
        .unwrap();

        let remaining: i64 = sqlx::query("SELECT COUNT(*) FROM iface_metrics_5s")
            .fetch_one(&pool)
            .await
            .unwrap()
            .get(0);
        assert_eq!(remaining, 1, "expired iface row deleted, recent row survives");
    }

    #[tokio::test]
    async fn rebuild_global_stats_cache_matches_summaries() {
        let (_dir, pool) = test_pool().await;

        let a = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        let b = test_metric(1_000, 2, 66_000, 400, 800, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![a, b], vec![], vec![])).await.unwrap();

        let rebuilt = rebuild_global_stats_cache(&pool).await.unwrap();
        assert_eq!(rebuilt.total_connect_count, 2);
        assert_eq!(rebuilt.total_ingress_bytes, 500);

        let stats = query_global_stats(&pool).await.unwrap();
        assert_eq!(stats.total_connect_count, rebuilt.total_connect_count);
        assert_eq!(stats.total_ingress_bytes, rebuilt.total_ingress_bytes);
    }

    #[tokio::test]
    async fn history_limit_is_clamped_and_defaulted() {
        let (_dir, pool) = test_pool().await;

        let mut batch = PersistenceBatch::default();
        for cpu_id in 0..250u32 {
            batch.summary_metrics.push(test_metric(
                1_000 + cpu_id as u64,
                cpu_id,
                65_000 + cpu_id as u64,
                100,
                200,
                ConnectStatusType::Disabled,
            ));
        }
        apply_connect_batch(&pool, &batch).await.unwrap();

        let huge_limit = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams { limit: Some(usize::MAX), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(huge_limit.len(), 200, "limit capped at MAX_PAGE_SIZE");

        let no_limit =
            query_historical_summaries_complex(&pool, ConnectHistoryQueryParams::default())
                .await
                .unwrap();
        assert_eq!(no_limit.len(), 200, "missing limit defaults to MAX_PAGE_SIZE");

        let zero_limit = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams { limit: Some(0), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(zero_limit.len(), 1, "limit=0 clamped up to 1");
    }
}
