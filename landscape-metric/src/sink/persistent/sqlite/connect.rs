use std::collections::HashMap;
use std::time::{Duration, Instant};

use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectHistoryStatus,
    ConnectKey, ConnectMetricPoint, ConnectSortKey, ConnectStatusType, IpHistoryStat,
    MetricResolution, SortOrder,
};
use landscape_core::time::get_current_time_ms;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, Transaction};

use super::clean_ip_string;
use crate::agg::{Batch, BucketKind, BucketWrite};

impl BucketKind {
    fn table_name(self) -> &'static str {
        match self {
            Self::Minute => "conn_metrics_1m",
            Self::Hour => "conn_metrics_1h",
            Self::Day => "conn_metrics_1d",
        }
    }
}

pub(crate) const GLOBAL_STATS_CACHE_KEY: i64 = 1;

/// 历史查询单页条数上限,防止无界 LIMIT 导致慢查询/超大响应。
/// 注意:`limit=0` 表示不限制(见 `query_historical_summaries_complex`),
/// 该哨兵值不走本上限。
const MAX_PAGE_SIZE: usize = 200;
/// 历史查询翻页偏移上限,避免深分页拖垮 SQLite。
/// offset 被截断后,超出该上限的页会重复返回同一段数据;前端将
/// `total` 同步截断到该值(见 HistoryMetric.vue 的 MAX_PAGE_OFFSET),
/// 保证分页组件不会渲染出重复页。
const MAX_PAGE_OFFSET: usize = 10_000;

/// 按容量目标删除最旧数据,返回删除行数。
///
/// 收敛判定使用主库**逻辑占用**(`page_count - freelist_count` × page_size,见
/// `super::logical_main_size_bytes`):WAL 模式下已提交删除立即可见,无需每批
/// checkpoint,循环稳定收敛到 `target_bytes` 以下;物理文件缩小由调用方在循环
/// 结束后执行 checkpoint + vacuum 尽力完成。
///
/// `target_bytes`:
/// - `Some(target)`:cleanup 路径。逻辑占用超过 target 即开始删除(调用方按容量
///   上限的 90% 提前清理,给后续写入留余量),删到 ≤ target 或预算耗尽。
/// - `None`:热回收路径(已 SQLITE_FULL)。不按尺寸判定,直接删除最多
///   `max_delete_rows` 行,为一次写入重试腾出 freelist 空间。
///
/// `rebuild_cache` 仅 cleanup 路径开启,避免满库时频繁全表重建 global stats 缓存。
pub(crate) async fn enforce_database_size(
    pool: &SqlitePool,
    target_bytes: Option<u64>,
    max_delete_rows: u64,
    rebuild_cache: bool,
) -> Result<u64, sqlx::Error> {
    const DELETE_BATCH_SIZE: u64 = 1_000;
    let mut deleted = 0;
    loop {
        let over_target = match target_bytes {
            Some(target) => super::logical_main_size_bytes(pool).await? > target,
            None => true,
        };
        if !over_target || deleted >= max_delete_rows {
            break;
        }
        let rows = sqlx::query(&format!(
            "DELETE FROM conn_summaries WHERE rowid IN \
             (SELECT rowid FROM conn_summaries ORDER BY last_report_time ASC LIMIT {DELETE_BATCH_SIZE})"
        ))
        .execute(pool)
        .await?
        .rows_affected();
        if rows == 0 {
            let mut deleted_bucket_rows = 0;
            for table in ["conn_metrics_1m", "conn_metrics_1h", "conn_metrics_1d"] {
                let rows = sqlx::query(&format!(
                    "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY bucket_time ASC LIMIT {DELETE_BATCH_SIZE})"
                ))
                .execute(pool)
                .await?
                .rows_affected();
                deleted_bucket_rows += rows;
                if rows > 0 {
                    break;
                }
            }
            if deleted_bucket_rows == 0 {
                break;
            }
            deleted += deleted_bucket_rows;
        } else {
            deleted += rows;
        }
    }
    if deleted > 0 && rebuild_cache {
        rebuild_global_stats_cache(pool).await?;
    }
    Ok(deleted)
}

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
    // 桶表采用追加写模型:report_time 为桶内最后一条 metric 的完整时间(主键),
    // bucket_time 为对齐粒度桶标识(查询/分组/清理)。同一对齐桶可因时钟乱序
    // 存在多行,读侧按 bucket_time 分组取最新;写侧同 report_time 冲突直接忽略。
    for table in ["conn_metrics_1m", "conn_metrics_1h", "conn_metrics_1d"] {
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {table} (
                create_time INTEGER NOT NULL,
                cpu_id INTEGER NOT NULL,
                report_time INTEGER NOT NULL,
                bucket_time INTEGER NOT NULL,
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
        // cleanup 按 bucket_time 范围分片删除,无此索引时每次删除/取 MIN 都全表扫描,
        // 长时间占用写锁并撞上 batch 写入的 busy_timeout 导致丢批。
        sqlx::query(&format!(
            "CREATE INDEX IF NOT EXISTS idx_{table}_bucket_time_key
             ON {table} (bucket_time, create_time, cpu_id)"
        ))
        .execute(pool)
        .await?;
    }

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

async fn upsert_summary_tx(
    tx: &mut Transaction<'_, Sqlite>,
    metric: &landscape_common::metric::connect::ConnectMetric,
) -> Result<(), sqlx::Error> {
    let status: u8 = metric.status_type().into();
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
    .bind(metric.key().create_time as i64)
    .bind(metric.key().cpu_id as i64)
    .bind(clean_ip_string(&metric.src_ip()))
    .bind(clean_ip_string(&metric.dst_ip()))
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
    .bind(metric.create_time_ms() as i64)
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

/// 桶行追加写:同 (create_time, cpu_id, report_time) 冲突直接忽略。
/// 不对齐桶做读改写合并——同一对齐桶的多次发射(1h 刷新、时钟乱序)以多行共存,
/// 由读侧按 bucket_time 分组取最新,天然兼容不可变/追加写存储。
async fn insert_bucket_tx(
    tx: &mut Transaction<'_, Sqlite>,
    table: &str,
    write: &BucketWrite,
) -> Result<(), sqlx::Error> {
    let status: u8 = write.metric.status_type().into();
    sqlx::query(&format!(
        "INSERT INTO {table} (
            create_time, cpu_id, report_time, bucket_time, ifindex,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            status, create_time_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        ON CONFLICT (create_time, cpu_id, report_time) DO NOTHING"
    ))
    .bind(write.metric.key().create_time as i64)
    .bind(write.metric.key().cpu_id as i64)
    .bind(write.metric.report_time as i64)
    .bind(write.bucket_report_time as i64)
    .bind(write.metric.ifindex as i64)
    .bind(write.metric.ingress_bytes as i64)
    .bind(write.metric.ingress_packets as i64)
    .bind(write.metric.egress_bytes as i64)
    .bind(write.metric.egress_packets as i64)
    .bind(status as i64)
    .bind(write.metric.create_time_ms() as i64)
    .execute(tx.as_mut())
    .await?;

    Ok(())
}

/// 将一聚合批次(桶 + 连接汇总)以单事务写入 connect.db。
pub(crate) async fn apply_connect_batch(
    pool: &SqlitePool,
    batch: &Batch,
) -> Result<(), sqlx::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut tx = pool.begin().await?;
    let last_calculate_time = get_current_time_ms().unwrap_or_default();

    // 批量查询本批次涉及的旧汇总值。SQLite 对 bind 参数数量有限制，
    // 因此按参数预算分块（每个 key 需要两个参数）。
    let mut keys: Vec<ConnectKey> =
        batch.summary_metrics.iter().map(|metric| metric.key()).collect();
    keys.sort_by_key(|key| (key.create_time, key.cpu_id));
    keys.dedup();
    let mut totals: HashMap<ConnectKey, SummaryTotals> = HashMap::with_capacity(keys.len());
    const MAX_KEYS_PER_QUERY: usize = 400;
    for key_chunk in keys.chunks(MAX_KEYS_PER_QUERY) {
        let mut qb = QueryBuilder::<Sqlite>::new(
            "SELECT create_time, cpu_id, total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts
            FROM conn_summaries WHERE (create_time, cpu_id) IN (",
        );
        let mut first = true;
        for key in key_chunk {
            if !first {
                qb.push(", ");
            }
            first = false;
            qb.push("(");
            qb.push_bind(key.create_time as i64);
            qb.push(", ");
            qb.push_bind(key.cpu_id as i64);
            qb.push(")");
        }
        qb.push(")");
        for row in qb.build().fetch_all(tx.as_mut()).await? {
            totals.insert(
                ConnectKey {
                    create_time: row.get::<i64, _>(0).max(0) as u64,
                    cpu_id: row.get::<i64, _>(1).max(0) as u32,
                },
                SummaryTotals {
                    total_ingress_bytes: row.get::<i64, _>(2).max(0) as u64,
                    total_egress_bytes: row.get::<i64, _>(3).max(0) as u64,
                    total_ingress_pkts: row.get::<i64, _>(4).max(0) as u64,
                    total_egress_pkts: row.get::<i64, _>(5).max(0) as u64,
                },
            );
        }
    }

    for metric in &batch.summary_metrics {
        let previous_totals = totals.get(&metric.key()).copied();
        upsert_summary_tx(&mut tx, metric).await?;
        let merged_totals = previous_totals
            .map(|totals| totals.merge_metric(metric))
            .unwrap_or_else(|| SummaryTotals::from_metric(metric));
        let delta = GlobalStatsDelta::from_summary_change(previous_totals, merged_totals);
        apply_global_stats_delta_tx(&mut tx, delta, last_calculate_time).await?;
        // 同一批次内同 key 的后续 summary 以合并后的值为基准。
        totals.insert(metric.key(), merged_totals);
    }

    for kind in [BucketKind::Minute, BucketKind::Hour, BucketKind::Day] {
        for write in batch.bucket_writes.iter().filter(|write| write.kind == kind) {
            insert_bucket_tx(&mut tx, kind.table_name(), write).await?;
        }
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
            bucket_time,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            status
        FROM (
            SELECT
                bucket_time,
                ingress_bytes, ingress_packets, egress_bytes, egress_packets,
                status,
                ROW_NUMBER() OVER (PARTITION BY bucket_time ORDER BY report_time DESC) AS rn
            FROM {table}
            WHERE create_time = ?1 AND cpu_id = ?2
        ) WHERE rn = 1
        ORDER BY bucket_time"
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
    ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
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
) -> Result<ConnectHistoryResponse, sqlx::Error> {
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

    let mut count_qb = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM conn_summaries");
    let mut count_has_where = false;
    push_connect_common_filters(&mut count_qb, &params, &mut count_has_where);
    push_connect_summary_filters(&mut count_qb, &params, &mut count_has_where);
    let total = count_qb.build().fetch_one(pool).await?.get::<i64, _>(0).max(0) as usize;

    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT
            create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto, flow_id, trace_id,
            ifindex, total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts, last_report_time, status, create_time_ms, gress
        FROM conn_summaries",
    );
    let mut has_where = false;
    push_connect_common_filters(&mut qb, &params, &mut has_where);
    push_connect_summary_filters(&mut qb, &params, &mut has_where);
    qb.push(" ORDER BY ")
        .push(sort_col)
        .push(" ")
        .push(sort_order)
        .push(", create_time DESC, cpu_id DESC");
    // limit 三态语义:
    // - `None`:缺省 100(前端分页的兜底默认值;老版本前端"不限"依赖缺省全量,
    //   已不再支持,调用方如需全量请显式传 0)。
    // - `Some(0)`:不限制,返回全部匹配行;与 connect_summary_max_rows /
    //   connect_db_max_mb 的 "0 = 不限制" 惯例保持一致。此时若带 offset,
    //   用 SQLite 的 `LIMIT -1 OFFSET n`(OFFSET 必须配 LIMIT 才合法)。
    // - `Some(n > 0)`:单页上限 clamp 到 MAX_PAGE_SIZE,offset clamp 到
    //   MAX_PAGE_OFFSET(与前端 itemCount 截断保持一致)。
    let offset = params.offset.unwrap_or(0).min(MAX_PAGE_OFFSET);
    match params.limit {
        Some(0) => {
            if offset > 0 {
                qb.push(format!(" LIMIT -1 OFFSET {}", offset));
            }
        }
        Some(limit) => {
            let limit = limit.clamp(1, MAX_PAGE_SIZE);
            qb.push(format!(" LIMIT {} OFFSET {}", limit, offset));
        }
        None => {
            qb.push(format!(" LIMIT 100 OFFSET {}", offset));
        }
    }

    let rows = qb.build().fetch_all(pool).await?;
    let items = rows
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
        .collect();
    Ok(ConnectHistoryResponse { items, total })
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
    // 单条 UPDATE 中完成聚合和 cache 写入。SQLite 会在该写语句开始时
    // 获取写锁，避免 SELECT 与后续 UPDATE 之间被并发写入插队。
    let mut tx = pool.begin().await?;
    let now = get_current_time_ms().unwrap_or_default();
    sqlx::query(
        "UPDATE conn_global_stats_cache
         SET total_ingress_bytes = (SELECT COALESCE(SUM(total_ingress_bytes), 0) FROM conn_summaries),
             total_egress_bytes = (SELECT COALESCE(SUM(total_egress_bytes), 0) FROM conn_summaries),
             total_ingress_pkts = (SELECT COALESCE(SUM(total_ingress_pkts), 0) FROM conn_summaries),
             total_egress_pkts = (SELECT COALESCE(SUM(total_egress_pkts), 0) FROM conn_summaries),
             total_connect_count = (SELECT COUNT(*) FROM conn_summaries),
             last_calculate_time = ?1
         WHERE cache_key = ?2",
    )
    .bind(now as i64)
    .bind(GLOBAL_STATS_CACHE_KEY)
    .execute(tx.as_mut())
    .await?;

    let row = sqlx::query(
        "SELECT total_ingress_bytes, total_egress_bytes,
                total_ingress_pkts, total_egress_pkts,
                total_connect_count, last_calculate_time
         FROM conn_global_stats_cache WHERE cache_key = ?1",
    )
    .bind(GLOBAL_STATS_CACHE_KEY)
    .fetch_one(tx.as_mut())
    .await?;
    let stats = ConnectGlobalStats {
        total_ingress_bytes: row.get::<i64, _>(0).max(0) as u64,
        total_egress_bytes: row.get::<i64, _>(1).max(0) as u64,
        total_ingress_pkts: row.get::<i64, _>(2).max(0) as u64,
        total_egress_pkts: row.get::<i64, _>(3).max(0) as u64,
        total_connect_count: row.get::<i64, _>(4).max(0) as u64,
        last_calculate_time: row.get::<i64, _>(5).max(0) as u64,
    };
    tx.commit().await?;
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
            >= stale_after_secs.saturating_mul(1000))
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

/// conn_summaries 条数硬顶:max_rows == 0 表示不限制。
/// 超过上限时按 last_report_time 升序淘汰最旧行,并通过
/// apply_global_stats_delta_tx 保持全局统计缓存一致。
pub(crate) async fn enforce_summary_max_rows(
    pool: &SqlitePool,
    max_rows: u64,
) -> Result<(), sqlx::Error> {
    if max_rows == 0 {
        return Ok(());
    }

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM conn_summaries").fetch_one(pool).await?;
    if total <= max_rows as i64 {
        return Ok(());
    }
    let excess = (total - max_rows as i64) as u64;

    let mut tx = pool.begin().await?;
    let row = sqlx::query(
        "SELECT
            COALESCE(SUM(total_ingress_bytes), 0),
            COALESCE(SUM(total_egress_bytes), 0),
            COALESCE(SUM(total_ingress_pkts), 0),
            COALESCE(SUM(total_egress_pkts), 0),
            COUNT(*)
        FROM conn_summaries
        WHERE (create_time, cpu_id) IN (
            SELECT create_time, cpu_id FROM conn_summaries ORDER BY last_report_time ASC LIMIT ?1
        )",
    )
    .bind(excess as i64)
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

    let deleted = sqlx::query(
        "DELETE FROM conn_summaries
         WHERE (create_time, cpu_id) IN (
            SELECT create_time, cpu_id FROM conn_summaries ORDER BY last_report_time ASC LIMIT ?1
         )",
    )
    .bind(excess as i64)
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
    cleanup_time_budget_ms: u64,
    cleanup_slice_window_secs: u64,
) -> Result<(), sqlx::Error> {
    let deadline = Instant::now() + Duration::from_millis(cleanup_time_budget_ms.max(1));
    let slice_window_ms = cleanup_slice_window_secs.max(1).saturating_mul(1000);

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
    // 按对齐桶时间分片删除;追加写模型下同一对齐桶可能有多行,一次删除整片。
    let mut cursor: Option<u64> = sqlx::query(&format!(
        "SELECT MIN(bucket_time) FROM {table} WHERE bucket_time >= 0 AND bucket_time < ?1"
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
        if slice_end <= slice_start {
            break;
        }
        sqlx::query(&format!("DELETE FROM {table} WHERE bucket_time >= ?1 AND bucket_time < ?2"))
            .bind(slice_start as i64)
            .bind(slice_end as i64)
            .execute(pool)
            .await?;

        cursor = sqlx::query(&format!(
            "SELECT MIN(bucket_time) FROM {table} WHERE bucket_time >= ?1 AND bucket_time < ?2"
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
    use crate::sink::persistent::sqlite::open_connect_pool;
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
        ConnectMetric::from_domain(
            create_time,
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
            egress_bytes,
            egress_bytes / 10,
            status,
        )
    }

    async fn test_pool() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open_connect_pool(&dir.path().join("connect.db"), 0).await.unwrap();
        (dir, pool)
    }

    fn batch_with(summary: Vec<ConnectMetric>, bucket_writes: Vec<BucketWrite>) -> Batch {
        Batch { summary_metrics: summary, bucket_writes }
    }

    #[tokio::test]
    async fn bucket_append_keeps_rows_and_reads_latest_per_aligned_bucket() {
        let (_dir, pool) = test_pool().await;
        let key = ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 1 };
        let bucket_time = 60_000u64;

        // 同一对齐桶的两次发射,raw report_time 不同 → 两行共存(追加写)。
        let first = test_metric(1_000, 1, 61_000, 100, 200, ConnectStatusType::Active);
        let mut second = first.clone();
        second.report_time = 62_000;
        second.ingress_bytes = 50;
        second.egress_bytes = 400;

        let mut batch = Batch::default();
        batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: first,
            bucket_report_time: bucket_time,
        });
        apply_connect_batch(&pool, &batch).await.unwrap();

        let mut second_batch = Batch::default();
        second_batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: second,
            bucket_report_time: bucket_time,
        });
        apply_connect_batch(&pool, &second_batch).await.unwrap();

        let points = query_metric_by_key(&pool, &key, MetricResolution::Minute).await.unwrap();
        assert_eq!(points.len(), 1, "latest row per aligned bucket, not two points");
        assert_eq!(points[0].ingress_bytes, 50, "latest raw row wins entirely");
        assert_eq!(points[0].egress_bytes, 400);
        assert_eq!(points[0].report_time, bucket_time, "point time is the aligned bucket");
    }

    #[tokio::test]
    async fn bucket_reads_latest_row_status_including_finalized_disabled() {
        let (_dir, pool) = test_pool().await;
        let key = ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 1 };
        let bucket_time = 60_000u64;

        // 旧行为 Disabled(2),新上报(更大 report_time)为 Active → 读侧取最新行。
        let older = test_metric(1_000, 1, 61_000, 100, 200, ConnectStatusType::Disabled);
        let mut newer = older.clone();
        newer.report_time = 62_000;
        newer.status = ConnectStatusType::Active.into();
        newer.ingress_bytes = 300;

        let mut batch = Batch::default();
        batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: older,
            bucket_report_time: bucket_time,
        });
        apply_connect_batch(&pool, &batch).await.unwrap();

        let mut second_batch = Batch::default();
        second_batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: newer,
            bucket_report_time: bucket_time,
        });
        apply_connect_batch(&pool, &second_batch).await.unwrap();

        let points = query_metric_by_key(&pool, &key, MetricResolution::Minute).await.unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(
            points[0].status,
            ConnectStatusType::Active,
            "status must follow the latest raw row, not MAX(status)"
        );
        assert_eq!(points[0].ingress_bytes, 300);
    }

    #[tokio::test]
    async fn bucket_duplicate_raw_key_is_ignored_on_append() {
        let (_dir, pool) = test_pool().await;
        let key = ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 1 };
        let bucket_time = 60_000u64;

        let first = test_metric(1_000, 1, 61_000, 100, 200, ConnectStatusType::Active);
        let mut second = first.clone();
        second.ingress_bytes = 999; // 相同 raw report_time → 冲突忽略

        let mut batch = Batch::default();
        batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: first,
            bucket_report_time: bucket_time,
        });
        apply_connect_batch(&pool, &batch).await.unwrap();

        let mut second_batch = Batch::default();
        second_batch.bucket_writes.push(BucketWrite {
            kind: BucketKind::Minute,
            metric: second,
            bucket_report_time: bucket_time,
        });
        apply_connect_batch(&pool, &second_batch).await.unwrap();

        let points = query_metric_by_key(&pool, &key, MetricResolution::Minute).await.unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].ingress_bytes, 100, "duplicate raw key row dropped");
    }

    #[tokio::test]
    async fn summary_upsert_uses_max_and_global_stats_tracks_single_connection() {
        let (_dir, pool) = test_pool().await;
        let key = ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 1 };

        let first = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![first.clone()], vec![])).await.unwrap();

        let second = test_metric(1_000, 1, 70_000, 300, 600, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![second], vec![])).await.unwrap();

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
        assert_eq!(history.total, 1);
        assert_eq!(history.items.len(), 1);
        assert_eq!(history.items[0].key, key);
        assert_eq!(history.items[0].total_ingress_bytes, 300);
    }

    #[tokio::test]
    async fn distinct_connections_count_independently_in_global_stats() {
        let (_dir, pool) = test_pool().await;

        let a = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        let b = test_metric(1_000, 2, 66_000, 400, 800, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![a, b], vec![])).await.unwrap();

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
        apply_connect_batch(&pool, &batch_with(vec![old, recent], vec![])).await.unwrap();

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
        assert_eq!(rows.total, 1);
        assert_eq!(rows.items.len(), 1);
        assert_eq!(rows.items[0].key.cpu_id, 2);

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
        apply_connect_batch(&pool, &batch_with(vec![old, recent], vec![])).await.unwrap();

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
        assert_eq!(rows.total, 1);
        assert_eq!(rows.items.len(), 1);
        assert_eq!(rows.items[0].key.cpu_id, 2);
    }

    #[tokio::test]
    async fn cleanup_old_buckets_deletes_expired_slices() {
        let (_dir, pool) = test_pool().await;

        let expired = test_metric(1_000, 1, 55_000, 100, 200, ConnectStatusType::Active);
        let kept = test_metric(1_000, 2, 95_000, 100, 200, ConnectStatusType::Active);
        let mut batch = Batch::default();
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
            1_000,
            60,
        )
        .await
        .unwrap();

        let points = query_metric_by_key(
            &pool,
            &ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 1 },
            MetricResolution::Minute,
        )
        .await
        .unwrap();
        assert!(points.is_empty(), "expired bucket deleted");

        let kept_points = query_metric_by_key(
            &pool,
            &ConnectKey { create_time: 1_000 * 1_000_000, cpu_id: 2 },
            MetricResolution::Minute,
        )
        .await
        .unwrap();
        assert_eq!(kept_points.len(), 1, "retained bucket survives");
    }

    #[tokio::test]
    async fn rebuild_global_stats_cache_matches_summaries() {
        let (_dir, pool) = test_pool().await;

        let a = test_metric(1_000, 1, 65_000, 100, 200, ConnectStatusType::Disabled);
        let b = test_metric(1_000, 2, 66_000, 400, 800, ConnectStatusType::Disabled);
        apply_connect_batch(&pool, &batch_with(vec![a, b], vec![])).await.unwrap();

        let rebuilt = rebuild_global_stats_cache(&pool).await.unwrap();
        assert_eq!(rebuilt.total_connect_count, 2);
        assert_eq!(rebuilt.total_ingress_bytes, 500);

        let stats = query_global_stats(&pool).await.unwrap();
        assert_eq!(stats.total_connect_count, rebuilt.total_connect_count);
        assert_eq!(stats.total_ingress_bytes, rebuilt.total_ingress_bytes);
    }

    #[tokio::test]
    async fn history_limit_and_offset_are_clamped() {
        let (_dir, pool) = test_pool().await;

        let mut batch = Batch::default();
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
        assert_eq!(huge_limit.total, 250);
        assert_eq!(huge_limit.items.len(), 200, "limit capped at MAX_PAGE_SIZE");

        let no_limit =
            query_historical_summaries_complex(&pool, ConnectHistoryQueryParams::default())
                .await
                .unwrap();
        assert_eq!(no_limit.items.len(), 100, "missing limit uses bounded default page size");

        let unlimited = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams { limit: Some(0), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(unlimited.items.len(), 250, "limit=0 means unlimited (all rows)");

        let unlimited_with_offset = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams {
                limit: Some(0),
                offset: Some(50),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            unlimited_with_offset.items.len(),
            200,
            "limit=0 with offset keeps all remaining rows via LIMIT -1 OFFSET"
        );

        let second_page = query_historical_summaries_complex(
            &pool,
            ConnectHistoryQueryParams {
                limit: Some(50),
                offset: Some(50),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(second_page.total, 250);
        assert_eq!(second_page.items.len(), 50);
    }

    #[tokio::test]
    async fn large_summary_batch_is_split_by_sqlite_parameter_budget() {
        let (_dir, pool) = test_pool().await;
        let mut batch = Batch::default();
        for cpu_id in 0..1_000u32 {
            batch.summary_metrics.push(test_metric(
                10_000 + cpu_id as u64,
                cpu_id,
                65_000 + cpu_id as u64,
                10,
                20,
                ConnectStatusType::Disabled,
            ));
        }
        apply_connect_batch(&pool, &batch).await.unwrap();
        let stats = query_global_stats(&pool).await.unwrap();
        assert_eq!(stats.total_connect_count, 1_000);
        assert_eq!(stats.total_ingress_bytes, 10_000);
    }

    #[test]
    fn bucket_table_name_maps_to_resolution_tables() {
        assert_eq!(BucketKind::Minute.table_name(), "conn_metrics_1m");
        assert_eq!(BucketKind::Hour.table_name(), "conn_metrics_1h");
        assert_eq!(BucketKind::Day.table_name(), "conn_metrics_1d");
    }

    #[tokio::test]
    async fn global_stats_stale_is_stale_without_row_or_zero_time() {
        let (_dir, pool) = test_pool().await;

        sqlx::query(
            "UPDATE conn_global_stats_cache SET last_calculate_time = 0 WHERE cache_key = 1",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(global_stats_stale(&pool, 86_400).await.unwrap(), "zero time is stale");

        sqlx::query("DELETE FROM conn_global_stats_cache WHERE cache_key = 1")
            .execute(&pool)
            .await
            .unwrap();
        assert!(global_stats_stale(&pool, 86_400).await.unwrap(), "missing row is stale");
    }

    #[tokio::test]
    async fn global_stats_stale_respects_threshold() {
        let (_dir, pool) = test_pool().await;
        let stale_after_secs = 86_400;
        let threshold_ms = stale_after_secs * 1000;
        let now = get_current_time_ms().unwrap_or_default();

        sqlx::query(
            "UPDATE conn_global_stats_cache SET last_calculate_time = ?1 WHERE cache_key = 1",
        )
        .bind((now.saturating_sub(threshold_ms).saturating_sub(60_000)) as i64)
        .execute(&pool)
        .await
        .unwrap();
        assert!(global_stats_stale(&pool, stale_after_secs).await.unwrap(), "older than threshold");

        sqlx::query(
            "UPDATE conn_global_stats_cache SET last_calculate_time = ?1 WHERE cache_key = 1",
        )
        .bind((now + 60_000) as i64)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            !global_stats_stale(&pool, stale_after_secs).await.unwrap(),
            "fresh time stays non-stale"
        );
    }

    fn build_common_filters_sql(params: &ConnectHistoryQueryParams) -> String {
        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM conn_summaries");
        let mut has_where = false;
        push_connect_common_filters(&mut qb, params, &mut has_where);
        qb.sql().to_string()
    }

    #[test]
    fn connect_common_filters_build_where_clauses() {
        let params = ConnectHistoryQueryParams {
            start_time: Some(1_000),
            end_time: Some(2_000),
            src_ip: Some("10.0.0".to_string()),
            dst_ip: Some("10.0.1".to_string()),
            flow_id: Some(7),
            ifindex: Some(42),
            ..Default::default()
        };
        let sql = build_common_filters_sql(&params);
        assert!(sql.starts_with("SELECT * FROM conn_summaries WHERE "));
        assert!(sql.contains("last_report_time >= "));
        assert!(sql.contains("last_report_time <= "));
        assert!(sql.contains("src_ip LIKE "));
        assert!(sql.contains("dst_ip LIKE "));
        assert!(sql.contains("flow_id = "));
        assert!(sql.contains("ifindex = "));
        assert_eq!(sql.matches(" WHERE ").count(), 1, "single WHERE keyword");
        assert_eq!(sql.matches(" AND ").count(), 5, "one AND per extra filter");
    }

    #[test]
    fn connect_common_filters_without_params_emit_no_where() {
        let sql = build_common_filters_sql(&ConnectHistoryQueryParams::default());
        assert_eq!(sql, "SELECT * FROM conn_summaries");
        let empty_ip = ConnectHistoryQueryParams {
            src_ip: Some(String::new()),
            dst_ip: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(build_common_filters_sql(&empty_ip), "SELECT * FROM conn_summaries");
    }

    #[test]
    fn connect_summary_filters_build_where_clauses() {
        let params = ConnectHistoryQueryParams {
            port_start: Some(8_000),
            port_end: Some(9_000),
            l3_proto: Some(4),
            l4_proto: Some(6),
            status: Some(1),
            gress: Some(0),
            ..Default::default()
        };
        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM conn_summaries");
        let mut has_where = false;
        push_connect_summary_filters(&mut qb, &params, &mut has_where);
        let sql = qb.sql().to_string();
        assert!(sql.contains("src_port = "));
        assert!(sql.contains("dst_port = "));
        assert!(sql.contains("l3_proto = "));
        assert!(sql.contains("l4_proto = "));
        assert!(sql.contains("status = "));
        assert!(sql.contains("gress = "));
    }

    #[test]
    fn connect_summary_filters_without_params_emit_no_where() {
        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM conn_summaries");
        let mut has_where = false;
        push_connect_summary_filters(
            &mut qb,
            &ConnectHistoryQueryParams::default(),
            &mut has_where,
        );
        assert_eq!(qb.sql(), "SELECT * FROM conn_summaries");
    }

    #[tokio::test]
    async fn row_cap_eviction_keeps_global_stats_consistent() {
        let (_dir, pool) = test_pool().await;
        for i in 0..5u64 {
            apply_connect_batch(
                &pool,
                &batch_with(
                    vec![test_metric(
                        1_000 + i,
                        0,
                        65_000 + i,
                        100,
                        200,
                        ConnectStatusType::Disabled,
                    )],
                    vec![],
                ),
            )
            .await
            .unwrap();
        }

        let before = query_global_stats(&pool).await.unwrap();
        assert_eq!(before.total_ingress_bytes, 500);
        assert_eq!(before.total_egress_bytes, 1_000);
        assert_eq!(before.total_connect_count, 5);

        enforce_summary_max_rows(&pool, 3).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conn_summaries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 3);

        let after = query_global_stats(&pool).await.unwrap();
        assert_eq!(after.total_ingress_bytes, 300);
        assert_eq!(after.total_egress_bytes, 600);
        assert_eq!(after.total_connect_count, 3);
    }

    #[tokio::test]
    async fn row_cap_zero_means_unlimited() {
        let (_dir, pool) = test_pool().await;
        for i in 0..5u64 {
            apply_connect_batch(
                &pool,
                &batch_with(
                    vec![test_metric(
                        1_000 + i,
                        0,
                        65_000 + i,
                        10,
                        20,
                        ConnectStatusType::Disabled,
                    )],
                    vec![],
                ),
            )
            .await
            .unwrap();
        }

        enforce_summary_max_rows(&pool, 0).await.unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conn_summaries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn row_cap_no_op_when_under_limit() {
        let (_dir, pool) = test_pool().await;
        for i in 0..3u64 {
            apply_connect_batch(
                &pool,
                &batch_with(
                    vec![test_metric(
                        1_000 + i,
                        0,
                        65_000 + i,
                        50,
                        100,
                        ConnectStatusType::Disabled,
                    )],
                    vec![],
                ),
            )
            .await
            .unwrap();
        }

        let before = query_global_stats(&pool).await.unwrap();
        enforce_summary_max_rows(&pool, 10).await.unwrap();
        let after = query_global_stats(&pool).await.unwrap();
        assert_eq!(before.total_ingress_bytes, after.total_ingress_bytes);
        assert_eq!(before.total_connect_count, after.total_connect_count);
    }

    #[tokio::test]
    async fn enforce_database_size_respects_delete_budget() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("connect.db");
        let pool = open_connect_pool(&db_path, 0).await.unwrap();

        let mut batch = Batch::default();
        for i in 0..2_500u32 {
            batch.summary_metrics.push(test_metric(
                i as u64,
                1,
                100_000 + i as u64,
                100,
                200,
                ConnectStatusType::Active,
            ));
        }
        apply_connect_batch(&pool, &batch).await.unwrap();

        // 目标极小 → 必须删除;预算 1_000 行,单次执行不得超删。
        let deleted = enforce_database_size(&pool, Some(1), 1_000, true).await.unwrap();
        assert!(deleted <= 1_000, "delete budget must cap single-run deletions");

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conn_summaries")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(total, 2_500 - deleted as i64);

        // 预算耗尽即停,不会在一个预算窗口内把库删空。
        assert!(total > 0, "delete budget must not exhaust the table in one run");

        // 新的预算窗口可继续收敛(按行数收敛,而非一次清空)。
        let deleted_again = enforce_database_size(&pool, Some(1), 1_000, true).await.unwrap();
        assert!(deleted_again > 0);

        pool.close().await;
    }

    #[tokio::test]
    async fn enforce_database_size_converges_to_target_not_budget() {
        // 回归:清理必须收敛到目标尺寸,而不是删满整个删除预算。
        // 旧实现以物理文件大小为判定,而 WAL 模式下删除不缩文件,导致
        // 每次清理都删满预算;新实现以主库逻辑占用判定,删到目标即停。
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("connect.db");
        let pool = open_connect_pool(&db_path, 0).await.unwrap();

        let mut batch = Batch::default();
        for i in 0..10_000u32 {
            batch.summary_metrics.push(test_metric(
                i as u64,
                1,
                100_000 + i as u64,
                100,
                200,
                ConnectStatusType::Active,
            ));
        }
        apply_connect_batch(&pool, &batch).await.unwrap();
        let logical_before = super::super::logical_main_size_bytes(&pool).await.unwrap();

        // 目标 = 当前逻辑占用的一半:预期删除约一半数据后即停止,
        // 远小于 10_000 的预算。
        let target = logical_before / 2;
        let deleted = enforce_database_size(&pool, Some(target), 10_000, true).await.unwrap();
        let logical_after = super::super::logical_main_size_bytes(&pool).await.unwrap();

        assert!(
            logical_after <= target,
            "cleanup must converge to the target (after={logical_after}, target={target})"
        );
        assert!(
            deleted < 10_000,
            "cleanup must stop at the target, not burn the whole budget (deleted={deleted})"
        );
        assert!(deleted > 0, "over-target database must trigger deletion");

        // 已收敛后再次清理:不再删除任何行。
        let deleted_idle = enforce_database_size(&pool, Some(target), 10_000, true).await.unwrap();
        assert_eq!(deleted_idle, 0, "under-target database must not delete rows");

        pool.close().await;
    }
}
