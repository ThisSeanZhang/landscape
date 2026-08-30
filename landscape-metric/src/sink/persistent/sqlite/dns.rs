use futures_util::StreamExt;
use hdrhistogram::serialization::{Deserializer, Serializer, V2Serializer};
use landscape_common::metric::connect::SortOrder;
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSortKey, DnsStatEntry, DnsSummaryQueryParams, DnsSummaryResponse,
};
use std::time::{Duration, Instant};

use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

use crate::agg::dns_bucket::{DnsBucketRow, DnsCounters, DnsSummaryParts};

use super::clean_ip_string;

/// 延迟统计排除的 status;与内存窗口一致,仅 Normal/NxDomain 计入。
/// NxDomain 含大量本地/缓存秒回查询(拦截 TLD、缓存 NXDOMAIN、被类型过滤的 NXDOMAIN),
/// 耗时 0~1ms,故 p50/p95/p99 显示 1ms 属正常,并非 filter 等被计入。
const LATENCY_EXCLUDE: &str = "'\"block\"', '\"filter\"', '\"error\"', '\"local\"', '\"hit\"'";

const PERCENTILE_QUANTILES: [f64; 3] = [0.50, 0.95, 0.99];

/// 历史查询单页条数上限,防止无界 LIMIT 导致慢查询/超大响应。
const MAX_PAGE_SIZE: usize = 200;
/// 历史查询翻页偏移上限。
const MAX_PAGE_OFFSET: usize = 10_000;

/// 按容量目标删除最旧数据,返回删除行数。语义与 connect 版本一致:收敛判定用
/// 主库逻辑占用(见 `super::logical_main_size_bytes`),`target_bytes` 为 `None` 时
/// 表示热回收路径(已 SQLITE_FULL),不按尺寸判定,直接删除至多 `max_delete_rows` 行。
pub(crate) async fn enforce_database_size(
    pool: &SqlitePool,
    target_bytes: Option<u64>,
    max_delete_rows: u64,
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
            "DELETE FROM dns_metrics WHERE rowid IN \
             (SELECT rowid FROM dns_metrics ORDER BY report_time ASC LIMIT {DELETE_BATCH_SIZE})"
        ))
        .execute(pool)
        .await?
        .rows_affected();
        if rows == 0 {
            let mut deleted_bucket_rows = 0;
            for table in [
                "dns_metrics_1m",
                "dns_top_domains_1m",
                "dns_top_clients_1m",
                "dns_top_blocked_1m",
                "dns_slowest_1m",
            ] {
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
    Ok(deleted)
}

pub(crate) async fn initialize_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_metrics (
            flow_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            query_type TEXT NOT NULL,
            response_code TEXT NOT NULL,
            report_time INTEGER NOT NULL,
            duration_ms INTEGER NOT NULL,
            src_ip TEXT NOT NULL,
            answers TEXT NOT NULL,
            status TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_dns_metrics_time ON dns_metrics (report_time)")
        .execute(pool)
        .await?;

    // 1m 预聚合桶(追加写):report_time 为批内最后一条 metric 的完整时间(主键),
    // bucket_time 为分钟对齐桶标识。同一 bucket_time 允许多行——多个批次贡献
    // 同一分钟各自成行(纯追加,不累加),读侧按 bucket_time 逐行合并
    // (SUM 计数 + 直方图合并 + top union);同 report_time 冲突直接忽略。
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_metrics_1m (
            flow_id INTEGER NOT NULL,
            bucket_time INTEGER NOT NULL,
            report_time INTEGER NOT NULL,
            total_queries INTEGER NOT NULL,
            total_effective_queries INTEGER NOT NULL,
            cache_hit_count INTEGER NOT NULL,
            total_v4 INTEGER NOT NULL,
            hit_count_v4 INTEGER NOT NULL,
            total_v6 INTEGER NOT NULL,
            hit_count_v6 INTEGER NOT NULL,
            total_other INTEGER NOT NULL,
            hit_count_other INTEGER NOT NULL,
            block_count INTEGER NOT NULL,
            filter_count INTEGER NOT NULL,
            nxdomain_count INTEGER NOT NULL,
            error_count INTEGER NOT NULL,
            latency_histogram BLOB NOT NULL,
            PRIMARY KEY (flow_id, report_time)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dns_metrics_1m_bucket_time
         ON dns_metrics_1m (bucket_time, flow_id)",
    )
    .execute(pool)
    .await?;

    // 每分钟 top-k 桶表:union+重排服务 dashboard 的 top 列表。
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_top_domains_1m (
            flow_id INTEGER NOT NULL,
            bucket_time INTEGER NOT NULL,
            report_time INTEGER NOT NULL,
            domain TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (flow_id, report_time, domain)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dns_top_domains_1m_bucket_time
         ON dns_top_domains_1m (bucket_time, flow_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_top_clients_1m (
            flow_id INTEGER NOT NULL,
            bucket_time INTEGER NOT NULL,
            report_time INTEGER NOT NULL,
            src_ip TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (flow_id, report_time, src_ip)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dns_top_clients_1m_bucket_time
         ON dns_top_clients_1m (bucket_time, flow_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_top_blocked_1m (
            flow_id INTEGER NOT NULL,
            bucket_time INTEGER NOT NULL,
            report_time INTEGER NOT NULL,
            domain TEXT NOT NULL,
            count INTEGER NOT NULL,
            PRIMARY KEY (flow_id, report_time, domain)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dns_top_blocked_1m_bucket_time
         ON dns_top_blocked_1m (bucket_time, flow_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_slowest_1m (
            flow_id INTEGER NOT NULL,
            bucket_time INTEGER NOT NULL,
            report_time INTEGER NOT NULL,
            domain TEXT NOT NULL,
            count INTEGER NOT NULL,
            sum_duration INTEGER NOT NULL,
            PRIMARY KEY (flow_id, report_time, domain)
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dns_slowest_1m_bucket_time
         ON dns_slowest_1m (bucket_time, flow_id)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

fn normalize_domain(domain: &mut String) {
    if domain.ends_with('.') && domain.len() > 1 {
        domain.pop();
    }
}

/// 批量插入 DNS 记录(单事务),answers/status 以 JSON 字符串存储。
pub(crate) async fn insert_dns_batch(
    pool: &SqlitePool,
    metrics: &[DnsMetric],
) -> Result<(), sqlx::Error> {
    if metrics.is_empty() {
        return Ok(());
    }

    super::run_write_tx(pool, metrics, |conn, metrics| {
        Box::pin(async move {
            for metric in *metrics {
                let mut answers = metric.answers.iter().take(64).cloned().collect::<Vec<_>>();
                while serde_json::to_vec(&answers).map(|json| json.len()).unwrap_or(0) > 16 * 1024 {
                    if answers.pop().is_none() {
                        break;
                    }
                }
                let answers_json =
                    serde_json::to_string(&answers).unwrap_or_else(|_| "[]".to_string());
                let status_json = serde_json::to_string(&metric.status).unwrap_or_default();
                sqlx::query(
                    "INSERT INTO dns_metrics (
                        flow_id, domain, query_type, response_code,
                        report_time, duration_ms, src_ip, answers, status
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .bind(metric.flow_id as i64)
                .bind(metric.domain.clone())
                .bind(metric.query_type.clone())
                .bind(metric.response_code.clone())
                .bind(metric.report_time as i64)
                .bind(metric.duration_ms as i64)
                .bind(clean_ip_string(&metric.src_ip))
                .bind(answers_json)
                .bind(status_json)
                .execute(&mut *conn)
                .await?;
            }
            Ok(())
        })
    })
    .await
}

/// 1m 预聚合桶批量落库(单事务,追加写)。
/// 桶行由 DNS writer 从原始行批次构建(writer 是桶的唯一数据源);同一 bucket_time
/// 多行是设计内行为:多批次贡献同一分钟各自成行,读侧逐行合并得到正确聚合。
/// 同 (flow_id, report_time) 冲突直接忽略(≈重复批次);top 表同键冲突同样忽略。
pub(crate) async fn insert_dns_bucket_rows(
    pool: &SqlitePool,
    rows: &[DnsBucketRow],
) -> Result<(), sqlx::Error> {
    if rows.is_empty() {
        return Ok(());
    }

    super::run_write_tx(pool, rows, |conn, rows| {
        Box::pin(async move {
            for row in *rows {
                let mut histogram_blob = Vec::new();
                V2Serializer::new()
                    .serialize(&row.latency, &mut histogram_blob)
                    .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;

                sqlx::query(
                    "INSERT INTO dns_metrics_1m (
                        flow_id, bucket_time, report_time,
                        total_queries, total_effective_queries, cache_hit_count,
                        total_v4, hit_count_v4, total_v6, hit_count_v6,
                        total_other, hit_count_other, block_count, filter_count,
                        nxdomain_count, error_count, latency_histogram
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
                    ON CONFLICT (flow_id, report_time) DO NOTHING",
                )
                .bind(row.flow_id as i64)
                .bind(row.bucket_time as i64)
                .bind(row.report_time as i64)
                .bind(row.counts.total_queries as i64)
                .bind(row.counts.total_effective_queries as i64)
                .bind(row.counts.cache_hit_count as i64)
                .bind(row.counts.total_v4 as i64)
                .bind(row.counts.hit_count_v4 as i64)
                .bind(row.counts.total_v6 as i64)
                .bind(row.counts.hit_count_v6 as i64)
                .bind(row.counts.total_other as i64)
                .bind(row.counts.hit_count_other as i64)
                .bind(row.counts.block_count as i64)
                .bind(row.counts.filter_count as i64)
                .bind(row.counts.nxdomain_count as i64)
                .bind(row.counts.error_count as i64)
                .bind(histogram_blob)
                .execute(&mut *conn)
                .await?;

                for (domain, count) in &row.top_domains {
                    sqlx::query(
                        "INSERT INTO dns_top_domains_1m (flow_id, bucket_time, report_time, domain, count)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT (flow_id, report_time, domain) DO NOTHING",
                    )
                    .bind(row.flow_id as i64)
                    .bind(row.bucket_time as i64)
                    .bind(row.report_time as i64)
                    .bind(domain.clone())
                    .bind(*count as i64)
                    .execute(&mut *conn)
                    .await?;
                }
                for (client, count) in &row.top_clients {
                    sqlx::query(
                        "INSERT INTO dns_top_clients_1m (flow_id, bucket_time, report_time, src_ip, count)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT (flow_id, report_time, src_ip) DO NOTHING",
                    )
                    .bind(row.flow_id as i64)
                    .bind(row.bucket_time as i64)
                    .bind(row.report_time as i64)
                    .bind(client.clone())
                    .bind(*count as i64)
                    .execute(&mut *conn)
                    .await?;
                }
                for (domain, count) in &row.top_blocked {
                    sqlx::query(
                        "INSERT INTO dns_top_blocked_1m (flow_id, bucket_time, report_time, domain, count)
                         VALUES (?1, ?2, ?3, ?4, ?5)
                         ON CONFLICT (flow_id, report_time, domain) DO NOTHING",
                    )
                    .bind(row.flow_id as i64)
                    .bind(row.bucket_time as i64)
                    .bind(row.report_time as i64)
                    .bind(domain.clone())
                    .bind(*count as i64)
                    .execute(&mut *conn)
                    .await?;
                }
                for (domain, count, sum_duration) in &row.slowest {
                    sqlx::query(
                        "INSERT INTO dns_slowest_1m (
                            flow_id, bucket_time, report_time, domain, count, sum_duration
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                         ON CONFLICT (flow_id, report_time, domain) DO NOTHING",
                    )
                    .bind(row.flow_id as i64)
                    .bind(row.bucket_time as i64)
                    .bind(row.report_time as i64)
                    .bind(domain.clone())
                    .bind(*count as i64)
                    .bind(*sum_duration as i64)
                    .execute(&mut *conn)
                    .await?;
                }
            }
            Ok(())
        })
    })
    .await
}

/// 桶段查询过滤器:按对齐桶时间半开区间 + 可选 flow。
fn push_bucket_filters(
    qb: &mut QueryBuilder<'_, Sqlite>,
    start_ms: u64,
    end_ms: u64,
    flow_id: Option<u32>,
    has_where: &mut bool,
) {
    if start_ms > 0 {
        push_clause(qb, has_where, "bucket_time >= ");
        qb.push_bind(start_ms as i64);
    }
    if end_ms > 0 {
        push_clause(qb, has_where, "bucket_time < ");
        qb.push_bind(end_ms as i64);
    }
    if let Some(flow_id) = flow_id {
        push_clause(qb, has_where, "flow_id = ");
        qb.push_bind(flow_id as i64);
    }
}

/// 读侧按对齐桶聚合的摘要片段:计数求和、直方图合并、top 行 union 重排。
/// 调用方负责传入分钟对齐的半开区间 [start_ms, end_ms)。
/// 读侧:对区间内全部桶行逐行合并(不假设同一 bucket_time 只有一行),与原始行
/// SQL 聚合语义一致。桶行由 writer 从原始行批次构建,与内存窗口无关。
pub(crate) async fn query_dns_summary_parts(
    pool: &SqlitePool,
    start_ms: u64,
    end_ms: u64,
    flow_id: Option<u32>,
) -> Result<DnsSummaryParts, sqlx::Error> {
    let mut parts = DnsSummaryParts::default();

    let mut base_qb = QueryBuilder::<Sqlite>::new(
        "SELECT
            total_queries, total_effective_queries, cache_hit_count,
            total_v4, hit_count_v4, total_v6, hit_count_v6,
            total_other, hit_count_other, block_count, filter_count,
            nxdomain_count, error_count, latency_histogram
        FROM dns_metrics_1m",
    );
    let mut has_where = false;
    push_bucket_filters(&mut base_qb, start_ms, end_ms, flow_id, &mut has_where);
    let rows = base_qb.build().fetch_all(pool).await?;
    let mut deserializer = Deserializer::new();
    for row in rows {
        let counts = DnsCounters {
            total_queries: row.get::<i64, _>(0).max(0) as u64,
            total_effective_queries: row.get::<i64, _>(1).max(0) as u64,
            cache_hit_count: row.get::<i64, _>(2).max(0) as u64,
            total_v4: row.get::<i64, _>(3).max(0) as u64,
            hit_count_v4: row.get::<i64, _>(4).max(0) as u64,
            total_v6: row.get::<i64, _>(5).max(0) as u64,
            hit_count_v6: row.get::<i64, _>(6).max(0) as u64,
            total_other: row.get::<i64, _>(7).max(0) as u64,
            hit_count_other: row.get::<i64, _>(8).max(0) as u64,
            block_count: row.get::<i64, _>(9).max(0) as u64,
            filter_count: row.get::<i64, _>(10).max(0) as u64,
            nxdomain_count: row.get::<i64, _>(11).max(0) as u64,
            error_count: row.get::<i64, _>(12).max(0) as u64,
        };
        parts.counts.merge(&counts);
        let blob: Vec<u8> = row.get(13);
        let histogram = deserializer
            .deserialize::<u64, _>(&mut &blob[..])
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let _ = parts.latency.add(&histogram);
    }

    parts.top_domains =
        query_top_map(pool, "dns_top_domains_1m", "domain", start_ms, end_ms, flow_id).await?;
    parts.top_clients =
        query_top_map(pool, "dns_top_clients_1m", "src_ip", start_ms, end_ms, flow_id).await?;
    parts.top_blocked =
        query_top_map(pool, "dns_top_blocked_1m", "domain", start_ms, end_ms, flow_id).await?;
    parts.slowest = query_slow_map(pool, start_ms, end_ms, flow_id).await?;

    Ok(parts)
}

async fn query_top_map(
    pool: &SqlitePool,
    table: &str,
    key_column: &str,
    start_ms: u64,
    end_ms: u64,
    flow_id: Option<u32>,
) -> Result<std::collections::HashMap<String, u64>, sqlx::Error> {
    let mut qb =
        QueryBuilder::<Sqlite>::new(format!("SELECT {key_column}, SUM(count) FROM {table}"));
    let mut has_where = false;
    push_bucket_filters(&mut qb, start_ms, end_ms, flow_id, &mut has_where);
    qb.push(format!(" GROUP BY 1 ORDER BY SUM(count) DESC LIMIT {TOP_MERGE_LIMIT}"));
    let rows = qb.build().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| (row.get::<String, _>(0), row.get::<i64, _>(1).max(0) as u64))
        .collect())
}

async fn query_slow_map(
    pool: &SqlitePool,
    start_ms: u64,
    end_ms: u64,
    flow_id: Option<u32>,
) -> Result<std::collections::HashMap<String, (u64, u64)>, sqlx::Error> {
    let mut qb = QueryBuilder::<Sqlite>::new(
        "SELECT domain, SUM(count), SUM(sum_duration) FROM dns_slowest_1m",
    );
    let mut has_where = false;
    push_bucket_filters(&mut qb, start_ms, end_ms, flow_id, &mut has_where);
    qb.push(format!(
        " GROUP BY 1 ORDER BY SUM(sum_duration) * 1.0 / SUM(count) DESC LIMIT {TOP_MERGE_LIMIT}"
    ));
    let rows = qb.build().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>(0),
                (row.get::<i64, _>(1).max(0) as u64, row.get::<i64, _>(2).max(0) as u64),
            )
        })
        .collect())
}

/// 每维度参与读侧合并的候选上限(按 SUM(count) 或平均耗时取 top-N),最终取 top-10。
const TOP_MERGE_LIMIT: i64 = 20;

fn push_clause(qb: &mut QueryBuilder<'_, Sqlite>, has_where: &mut bool, prefix: &str) {
    if !*has_where {
        qb.push(" WHERE ");
        *has_where = true;
    } else {
        qb.push(" AND ");
    }
    qb.push(prefix);
}

fn push_history_filters(
    qb: &mut QueryBuilder<'_, Sqlite>,
    params: &DnsHistoryQueryParams,
    has_where: &mut bool,
) {
    if let Some(start) = params.start_time {
        push_clause(qb, has_where, "report_time >= ");
        qb.push_bind(start as i64);
    }
    if let Some(end) = params.end_time {
        push_clause(qb, has_where, "report_time < ");
        qb.push_bind(end as i64);
    }
    if let Some(flow_id) = params.flow_id {
        push_clause(qb, has_where, "flow_id = ");
        qb.push_bind(flow_id as i64);
    }
    if let Some(mut domain) = params.domain.clone().filter(|domain| !domain.is_empty()) {
        normalize_domain(&mut domain);
        push_clause(qb, has_where, "domain LIKE ");
        qb.push_bind(format!("%{}%", domain));
    }
    if let Some(src_ip) = params.src_ip.as_ref().filter(|src_ip| !src_ip.is_empty()) {
        push_clause(qb, has_where, "src_ip LIKE ");
        qb.push_bind(format!("%{}%", src_ip));
    }
    if let Some(query_type) = params.query_type.as_ref().filter(|query_type| !query_type.is_empty())
    {
        push_clause(qb, has_where, "query_type = ");
        qb.push_bind(query_type.clone());
    }
    if let Some(status) = params.status {
        push_clause(qb, has_where, "status = ");
        qb.push_bind(serde_json::to_string(&status).unwrap_or_default());
    }
    if let Some(min_duration_ms) = params.min_duration_ms {
        push_clause(qb, has_where, "duration_ms >= ");
        qb.push_bind(min_duration_ms as i64);
    }
    if let Some(max_duration_ms) = params.max_duration_ms {
        push_clause(qb, has_where, "duration_ms <= ");
        qb.push_bind(max_duration_ms as i64);
    }
}

fn push_summary_filters(
    qb: &mut QueryBuilder<'_, Sqlite>,
    params: &DnsSummaryQueryParams,
    has_where: &mut bool,
) {
    if params.start_time > 0 {
        push_clause(qb, has_where, "report_time >= ");
        qb.push_bind(params.start_time as i64);
    }
    if params.end_time > 0 {
        push_clause(qb, has_where, "report_time < ");
        qb.push_bind(params.end_time as i64);
    }
    if let Some(flow_id) = params.flow_id {
        push_clause(qb, has_where, "flow_id = ");
        qb.push_bind(flow_id as i64);
    }
}

pub(crate) async fn query_dns_history(
    pool: &SqlitePool,
    params: DnsHistoryQueryParams,
) -> Result<DnsHistoryResponse, sqlx::Error> {
    let mut count_qb = QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM dns_metrics");
    let mut query_qb = QueryBuilder::<Sqlite>::new(
        "SELECT
            flow_id, domain, query_type, response_code, report_time, duration_ms, src_ip, answers, status
        FROM dns_metrics",
    );
    let mut has_where = false;
    push_history_filters(&mut query_qb, &params, &mut has_where);
    let mut count_has_where = false;
    push_history_filters(&mut count_qb, &params, &mut count_has_where);

    let total: i64 = count_qb.build().fetch_one(pool).await?.get(0);

    let sort_col = match params.sort_key.unwrap_or_default() {
        DnsSortKey::Time => "report_time",
        DnsSortKey::Domain => "domain",
        DnsSortKey::Duration => "duration_ms",
    };
    let sort_order = match params.sort_order.unwrap_or_default() {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    };
    let order_by = if sort_col == "report_time" {
        format!("{} {}", sort_col, sort_order)
    } else {
        format!("{} {}, report_time DESC", sort_col, sort_order)
    };
    let limit = params.limit.unwrap_or(20).clamp(1, MAX_PAGE_SIZE);
    let offset = params.offset.unwrap_or(0).min(MAX_PAGE_OFFSET);
    query_qb.push(" ORDER BY ").push(order_by);
    query_qb.push(format!(" LIMIT {}", limit));
    query_qb.push(format!(" OFFSET {}", offset));

    let rows = query_qb.build().fetch_all(pool).await?;
    let items = rows.iter().map(dns_metric_from_row).collect();

    Ok(DnsHistoryResponse { items, total: total.max(0) as usize })
}

/// 线性插值百分位(P50/P95/P99)
///
/// 流式读取 `ORDER BY duration_ms` 的结果,只保留各分位数对应插值位置的
/// 少量行(floor/ceil,去重后最多 6 个),O(1) 内存;超过最大 rank 后提前退出。
/// 调用方必须已配置好 `SELECT duration_ms ... [filters]`,本函数追加排序与 LIMIT。
async fn stream_latency_percentiles(
    pool: &SqlitePool,
    qb: &mut QueryBuilder<'_, Sqlite>,
    count: usize,
) -> Result<[f64; 3], sqlx::Error> {
    if count == 0 {
        return Ok([0.0; 3]);
    }

    let mut rank_floor = [0usize; 3];
    let mut rank_ceil = [0usize; 3];
    let mut fraction = [0.0f64; 3];
    let mut max_rank = 0usize;
    for (index, quantile) in PERCENTILE_QUANTILES.into_iter().enumerate() {
        let rank = quantile * (count as f64 - 1.0);
        let lower = rank.floor() as usize;
        let upper = rank.ceil() as usize;
        rank_floor[index] = lower;
        rank_ceil[index] = upper;
        fraction[index] = rank - lower as f64;
        max_rank = max_rank.max(upper);
    }

    qb.push(" ORDER BY duration_ms").push(format!(" LIMIT {}", max_rank.saturating_add(1)));
    let mut picked = [0.0f64; 6];
    let mut position = 0usize;
    let mut stream = qb.build().fetch(pool);
    while let Some(row) = stream.next().await {
        let row = row?;
        let value = row.get::<i64, _>(0).max(0) as f64;
        for index in 0..3 {
            if rank_floor[index] == position {
                picked[index * 2] = value;
            }
            if rank_ceil[index] == position {
                picked[index * 2 + 1] = value;
            }
        }
        position += 1;
        if position > max_rank {
            break;
        }
    }

    Ok(std::array::from_fn(|index| {
        picked[index * 2] + (picked[index * 2 + 1] - picked[index * 2]) * fraction[index]
    }))
}

/// 完整 summary:基础计数 + 分位数 + top 列表,全部从 dns_metrics 聚合。
pub(crate) async fn query_dns_summary(
    pool: &SqlitePool,
    params: DnsSummaryQueryParams,
) -> Result<DnsSummaryResponse, sqlx::Error> {
    let mut base_qb = QueryBuilder::<Sqlite>::new(format!(
        "SELECT
            COUNT(*),
            COUNT(CASE WHEN status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'A' AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'A' AND status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN query_type = 'AAAA' AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'AAAA' AND status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN query_type NOT IN ('A', 'AAAA') AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type NOT IN ('A', 'AAAA') AND status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"block\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"filter\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"nxdomain\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"error\"' THEN 1 END),
            AVG(CASE WHEN status NOT IN ({LATENCY_EXCLUDE}) THEN duration_ms END),
            MAX(CASE WHEN status NOT IN ({LATENCY_EXCLUDE}) THEN duration_ms END),
            COUNT(CASE WHEN status NOT IN ({LATENCY_EXCLUDE}) THEN 1 END)
        FROM dns_metrics"
    ));
    let mut has_where = false;
    push_summary_filters(&mut base_qb, &params, &mut has_where);
    let row = base_qb.build().fetch_one(pool).await?;
    let latency_count = row.get::<i64, _>(15).max(0) as usize;

    let mut duration_qb = QueryBuilder::<Sqlite>::new(format!(
        "SELECT duration_ms FROM dns_metrics WHERE status NOT IN ({LATENCY_EXCLUDE})"
    ));
    let mut duration_has_where = true;
    push_summary_filters(&mut duration_qb, &params, &mut duration_has_where);
    let [p50_duration_ms, p95_duration_ms, p99_duration_ms] =
        stream_latency_percentiles(pool, &mut duration_qb, latency_count).await?;

    let mut top_qb = QueryBuilder::<Sqlite>::new("SELECT src_ip, COUNT(*) as c FROM dns_metrics");
    let mut top_has_where = false;
    push_summary_filters(&mut top_qb, &params, &mut top_has_where);
    top_qb.push(" GROUP BY 1 ORDER BY c DESC LIMIT 10");
    let top_clients = query_top_entries(top_qb.build().fetch_all(pool).await?, false);

    let mut top_domain_qb =
        QueryBuilder::<Sqlite>::new("SELECT domain, COUNT(*) as c FROM dns_metrics");
    let mut top_domain_has_where = false;
    push_summary_filters(&mut top_domain_qb, &params, &mut top_domain_has_where);
    top_domain_qb.push(" GROUP BY 1 ORDER BY c DESC LIMIT 10");
    let top_domains = query_top_entries(top_domain_qb.build().fetch_all(pool).await?, false);

    let mut blocked_qb = QueryBuilder::<Sqlite>::new(
        "SELECT domain, COUNT(*) as c FROM dns_metrics WHERE status = '\"block\"'",
    );
    let mut blocked_has_where = true;
    push_summary_filters(&mut blocked_qb, &params, &mut blocked_has_where);
    blocked_qb.push(" GROUP BY 1 ORDER BY c DESC LIMIT 10");
    let top_blocked = query_top_entries(blocked_qb.build().fetch_all(pool).await?, false);

    let mut slowest_qb = QueryBuilder::<Sqlite>::new(format!(
        "SELECT domain, AVG(duration_ms) as avg_d, COUNT(*) as c
        FROM dns_metrics WHERE status NOT IN ({LATENCY_EXCLUDE})"
    ));
    let mut slowest_has_where = true;
    push_summary_filters(&mut slowest_qb, &params, &mut slowest_has_where);
    slowest_qb.push(" GROUP BY 1 HAVING c > 2 ORDER BY avg_d DESC LIMIT 10");
    let slowest_domains = query_top_entries(slowest_qb.build().fetch_all(pool).await?, true);

    Ok(DnsSummaryResponse {
        total_queries: row.get::<i64, _>(0).max(0) as usize,
        total_effective_queries: row.get::<i64, _>(2).max(0) as usize,
        cache_hit_count: row.get::<i64, _>(1).max(0) as usize,
        hit_count_v4: row.get::<i64, _>(4).max(0) as usize,
        hit_count_v6: row.get::<i64, _>(6).max(0) as usize,
        hit_count_other: row.get::<i64, _>(8).max(0) as usize,
        total_v4: row.get::<i64, _>(3).max(0) as usize,
        total_v6: row.get::<i64, _>(5).max(0) as usize,
        total_other: row.get::<i64, _>(7).max(0) as usize,
        block_count: row.get::<i64, _>(9).max(0) as usize,
        filter_count: row.get::<i64, _>(10).max(0) as usize,
        nxdomain_count: row.get::<i64, _>(11).max(0) as usize,
        error_count: row.get::<i64, _>(12).max(0) as usize,
        avg_duration_ms: row.get::<Option<f64>, _>(13).unwrap_or(0.0),
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms,
        max_duration_ms: row.get::<Option<i64>, _>(14).unwrap_or(0) as f64,
        top_clients,
        top_domains,
        top_blocked,
        slowest_domains,
    })
}

fn query_top_entries(rows: Vec<sqlx::sqlite::SqliteRow>, parse_value: bool) -> Vec<DnsStatEntry> {
    rows.into_iter()
        .map(|row| DnsStatEntry {
            name: row.get::<String, _>(0),
            count: row.get::<i64, _>(if parse_value { 2 } else { 1 }).max(0) as usize,
            value: if parse_value {
                Some(row.get::<Option<f64>, _>(1).unwrap_or(0.0))
            } else {
                None
            },
        })
        .collect()
}

fn dns_metric_from_row(row: &sqlx::sqlite::SqliteRow) -> DnsMetric {
    DnsMetric {
        flow_id: row.get::<i64, _>(0).max(0) as u32,
        domain: row.get::<String, _>(1),
        query_type: row.get::<String, _>(2),
        response_code: row.get::<String, _>(3),
        report_time: row.get::<i64, _>(4).max(0) as u64,
        duration_ms: row.get::<i64, _>(5).max(0) as u32,
        src_ip: row
            .get::<String, _>(6)
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        answers: serde_json::from_str(&row.get::<String, _>(7)).unwrap_or_default(),
        status: serde_json::from_str(&row.get::<String, _>(8)).unwrap_or_default(),
    }
}

fn push_range_filters(
    qb: &mut QueryBuilder<'_, Sqlite>,
    params: &DnsSummaryQueryParams,
    has_where: &mut bool,
) {
    if params.start_time > 0 {
        push_clause(qb, has_where, "report_time >= ");
        qb.push_bind(params.start_time as i64);
    }
    if params.end_time > 0 {
        push_clause(qb, has_where, "report_time < ");
        qb.push_bind(params.end_time as i64);
    }
    if let Some(flow_id) = params.flow_id {
        push_clause(qb, has_where, "flow_id = ");
        qb.push_bind(flow_id as i64);
    }
}

/// 轻量 summary(SQL 回退路径):仅基础计数与延迟分位数,语义与内存窗口一致。
/// 调用方负责将时间范围规范化为分钟对齐的半开区间 [start, end)。
pub(crate) async fn query_dns_lightweight_summary(
    pool: &SqlitePool,
    params: DnsSummaryQueryParams,
) -> Result<DnsLightweightSummaryResponse, sqlx::Error> {
    let mut base_qb = QueryBuilder::<Sqlite>::new(format!(
        "SELECT
            COUNT(*),
            COUNT(CASE WHEN status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'A' AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'A' AND status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN query_type = 'AAAA' AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'AAAA' AND status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN query_type NOT IN ('A', 'AAAA') AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type NOT IN ('A', 'AAAA') AND status = '\"hit\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"block\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"filter\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"nxdomain\"' THEN 1 END),
            COUNT(CASE WHEN status = '\"error\"' THEN 1 END),
            AVG(CASE WHEN status NOT IN ({LATENCY_EXCLUDE}) THEN duration_ms END),
            MAX(CASE WHEN status NOT IN ({LATENCY_EXCLUDE}) THEN duration_ms END),
            COUNT(CASE WHEN status NOT IN ({LATENCY_EXCLUDE}) THEN 1 END)
        FROM dns_metrics"
    ));
    let mut has_where = false;
    push_range_filters(&mut base_qb, &params, &mut has_where);
    let row = base_qb.build().fetch_one(pool).await?;
    let latency_count = row.get::<i64, _>(15).max(0) as usize;

    let mut duration_qb = QueryBuilder::<Sqlite>::new(format!(
        "SELECT duration_ms FROM dns_metrics WHERE status NOT IN ({LATENCY_EXCLUDE})"
    ));
    let mut duration_has_where = true;
    push_range_filters(&mut duration_qb, &params, &mut duration_has_where);
    let [p50_duration_ms, p95_duration_ms, p99_duration_ms] =
        stream_latency_percentiles(pool, &mut duration_qb, latency_count).await?;

    Ok(DnsLightweightSummaryResponse {
        total_queries: row.get::<i64, _>(0).max(0) as usize,
        total_effective_queries: row.get::<i64, _>(2).max(0) as usize,
        cache_hit_count: row.get::<i64, _>(1).max(0) as usize,
        hit_count_v4: row.get::<i64, _>(4).max(0) as usize,
        hit_count_v6: row.get::<i64, _>(6).max(0) as usize,
        hit_count_other: row.get::<i64, _>(8).max(0) as usize,
        total_v4: row.get::<i64, _>(3).max(0) as usize,
        total_v6: row.get::<i64, _>(5).max(0) as usize,
        total_other: row.get::<i64, _>(7).max(0) as usize,
        block_count: row.get::<i64, _>(9).max(0) as usize,
        filter_count: row.get::<i64, _>(10).max(0) as usize,
        nxdomain_count: row.get::<i64, _>(11).max(0) as usize,
        error_count: row.get::<i64, _>(12).max(0) as usize,
        avg_duration_ms: row.get::<Option<f64>, _>(13).unwrap_or(0.0),
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms,
        max_duration_ms: row.get::<Option<i64>, _>(14).unwrap_or(0) as f64,
    })
}

pub(crate) async fn cleanup_old_dns(
    pool: &SqlitePool,
    cutoff: u64,
    cleanup_time_budget_ms: u64,
    cleanup_slice_window_secs: u64,
) -> Result<u64, sqlx::Error> {
    let deadline = Instant::now() + Duration::from_millis(cleanup_time_budget_ms.max(1));
    let slice_window_ms = cleanup_slice_window_secs.max(1).saturating_mul(1000);
    let mut deleted_total = 0;

    loop {
        if Instant::now() >= deadline {
            break;
        }
        let next = sqlx::query(
            "SELECT MIN(report_time) FROM dns_metrics WHERE report_time >= 0 AND report_time < ?1",
        )
        .bind(cutoff as i64)
        .fetch_optional(pool)
        .await?
        .and_then(|row| row.get::<Option<i64>, _>(0))
        .map(|value| value.max(0) as u64);
        let Some(slice_start) = next else { break };
        let slice_end = slice_start.saturating_add(slice_window_ms).min(cutoff);
        if slice_end <= slice_start {
            break;
        }
        let deleted =
            sqlx::query("DELETE FROM dns_metrics WHERE report_time >= ?1 AND report_time < ?2")
                .bind(slice_start as i64)
                .bind(slice_end as i64)
                .execute(pool)
                .await?
                .rows_affected();
        deleted_total += deleted;
    }

    Ok(deleted_total)
}

const DNS_BUCKET_TABLES: [&str; 5] = [
    "dns_metrics_1m",
    "dns_top_domains_1m",
    "dns_top_clients_1m",
    "dns_top_blocked_1m",
    "dns_slowest_1m",
];

/// 按 retention 分片删除过期 1m 桶(含 4 张 top 表),受 cleanup_time_budget_ms 预算约束。
pub(crate) async fn cleanup_old_dns_buckets(
    pool: &SqlitePool,
    cutoff: u64,
    cleanup_time_budget_ms: u64,
    cleanup_slice_window_secs: u64,
) -> Result<(), sqlx::Error> {
    let deadline = Instant::now() + Duration::from_millis(cleanup_time_budget_ms.max(1));
    let slice_window_ms = cleanup_slice_window_secs.max(1).saturating_mul(1000);

    for table in DNS_BUCKET_TABLES {
        if Instant::now() >= deadline {
            break;
        }
        delete_bucket_table_in_slices(pool, table, cutoff, slice_window_ms, deadline).await?;
        if Instant::now() >= deadline {
            break;
        }
    }

    Ok(())
}

async fn delete_bucket_table_in_slices(
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
    use crate::sink::persistent::sqlite::open_dns_pool;
    use landscape_common::metric::dns::{DnsMetric, DnsOutcome, DnsSortKey};
    use std::net::{IpAddr, Ipv4Addr};

    fn dns_metric(
        flow_id: u32,
        domain: &str,
        query_type: &str,
        status: DnsOutcome,
        report_time: u64,
        duration_ms: u32,
    ) -> DnsMetric {
        DnsMetric {
            flow_id,
            domain: domain.to_string(),
            query_type: query_type.to_string(),
            response_code: "NOERROR".to_string(),
            status,
            report_time,
            duration_ms,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, flow_id as u8)),
            answers: Vec::new(),
        }
    }

    async fn test_pool() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open_dns_pool(&dir.path().join("dns.db"), 0).await.unwrap();
        (dir, pool)
    }

    #[tokio::test]
    async fn history_query_filters_paginates_and_normalizes_domain() {
        let (_dir, pool) = test_pool().await;
        insert_dns_batch(
            &pool,
            &[
                dns_metric(1, "example.com.", "A", DnsOutcome::Normal, 100_000, 10),
                dns_metric(2, "other.com", "AAAA", DnsOutcome::Block, 110_000, 20),
                dns_metric(3, "example.com", "A", DnsOutcome::Normal, 120_000, 30),
            ],
        )
        .await
        .unwrap();

        let response = query_dns_history(
            &pool,
            DnsHistoryQueryParams {
                start_time: Some(100_000),
                end_time: Some(121_000),
                limit: Some(10),
                sort_key: Some(DnsSortKey::Time),
                sort_order: Some(SortOrder::Asc),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(response.total, 3);
        assert_eq!(response.items.len(), 3);

        let filtered = query_dns_history(
            &pool,
            DnsHistoryQueryParams {
                domain: Some("example.com.".to_string()),
                limit: Some(10),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(filtered.total, 2, "trailing dot normalized");

        let exclusive_end = query_dns_history(
            &pool,
            DnsHistoryQueryParams {
                end_time: Some(120_000),
                limit: Some(10),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(
            exclusive_end.total, 2,
            "end_time is half-open: row at exactly end_time excluded"
        );

        let paginated = query_dns_history(
            &pool,
            DnsHistoryQueryParams {
                limit: Some(1),
                offset: Some(1),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(paginated.total, 3);
        assert_eq!(paginated.items.len(), 1);
    }

    #[tokio::test]
    async fn summary_counts_percentiles_and_top_lists() {
        let (_dir, pool) = test_pool().await;
        let metrics = vec![
            dns_metric(1, "hot.com", "A", DnsOutcome::Normal, 100_000, 10),
            dns_metric(2, "hot.com", "A", DnsOutcome::Normal, 100_001, 20),
            dns_metric(3, "hot.com", "A", DnsOutcome::Normal, 100_002, 30),
            dns_metric(4, "slow.com", "AAAA", DnsOutcome::Normal, 100_003, 100),
            dns_metric(5, "slow.com", "AAAA", DnsOutcome::Normal, 100_004, 110),
            dns_metric(6, "slow.com", "AAAA", DnsOutcome::Normal, 100_005, 90),
            dns_metric(7, "blocked.com", "A", DnsOutcome::Block, 100_006, 5),
            dns_metric(8, "cached.com", "A", DnsOutcome::Hit, 100_007, 1),
            dns_metric(9, "err.com", "A", DnsOutcome::Error, 100_008, 2),
        ];
        insert_dns_batch(&pool, &metrics).await.unwrap();

        let summary = query_dns_summary(
            &pool,
            DnsSummaryQueryParams {
                start_time: 100_000,
                end_time: 200_000,
                flow_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(summary.total_queries, 9);
        assert_eq!(summary.cache_hit_count, 1);
        assert_eq!(summary.total_effective_queries, 7);
        assert_eq!(summary.block_count, 1);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.total_v4, 4);
        assert_eq!(summary.total_v6, 3);

        assert_eq!(summary.avg_duration_ms, 60.0, "only normal latency counted");
        assert_eq!(summary.p50_duration_ms, 60.0, "linear interpolation of [10,20,30,90,100,110]");
        assert!((summary.p95_duration_ms - 107.5).abs() < 1e-9);
        assert!((summary.p99_duration_ms - 109.5).abs() < 1e-9);
        assert_eq!(summary.max_duration_ms, 110.0);

        let top_names: Vec<_> =
            summary.top_domains.iter().map(|entry| entry.name.as_str()).collect();
        assert!(top_names.contains(&"hot.com") && top_names.contains(&"slow.com"));
        assert_eq!(summary.top_domains.iter().map(|entry| entry.count).sum::<usize>(), 9);
        assert_eq!(summary.top_blocked[0].name, "blocked.com");
        assert_eq!(summary.slowest_domains[0].name, "slow.com");

        let unbounded = query_dns_summary(&pool, DnsSummaryQueryParams::default()).await.unwrap();
        assert_eq!(unbounded.total_queries, metrics.len());
    }

    #[tokio::test]
    async fn lightweight_summary_matches_counts_and_respects_range() {
        let (_dir, pool) = test_pool().await;
        let metrics = vec![
            dns_metric(1, "a.com", "A", DnsOutcome::Normal, 100_000, 10),
            dns_metric(2, "b.com", "A", DnsOutcome::Hit, 100_001, 1),
            dns_metric(3, "c.com", "AAAA", DnsOutcome::Normal, 100_002, 30),
            dns_metric(4, "d.com", "TXT", DnsOutcome::Block, 100_003, 5),
            dns_metric(5, "e.com", "A", DnsOutcome::NxDomain, 100_004, 50),
            dns_metric(6, "f.com", "A", DnsOutcome::Error, 100_005, 2),
        ];
        insert_dns_batch(&pool, &metrics).await.unwrap();

        let summary = query_dns_lightweight_summary(
            &pool,
            DnsSummaryQueryParams {
                start_time: 100_000,
                end_time: 200_000,
                flow_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(summary.total_queries, 6);
        assert_eq!(summary.cache_hit_count, 1);
        assert_eq!(summary.total_effective_queries, 4);
        assert_eq!(summary.total_v4, 3);
        assert_eq!(summary.hit_count_v4, 1);
        assert_eq!(summary.total_v6, 1);
        assert_eq!(summary.block_count, 1);
        assert_eq!(summary.nxdomain_count, 1);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.avg_duration_ms, 30.0, "only normal/nxdomain latency counted");
        assert_eq!(summary.max_duration_ms, 50.0);

        let narrowed = query_dns_lightweight_summary(
            &pool,
            DnsSummaryQueryParams {
                start_time: 100_004,
                end_time: 200_000,
                flow_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(narrowed.total_queries, 2);
    }

    #[tokio::test]
    async fn cleanup_old_dns_deletes_expired_rows() {
        let (_dir, pool) = test_pool().await;
        insert_dns_batch(
            &pool,
            &[
                dns_metric(1, "old.com", "A", DnsOutcome::Normal, 100_000, 10),
                dns_metric(2, "new.com", "A", DnsOutcome::Normal, 200_000, 10),
            ],
        )
        .await
        .unwrap();

        let deleted = cleanup_old_dns(&pool, 150_000, 1_000, 60).await.unwrap();
        assert_eq!(deleted, 1);

        let response = query_dns_history(&pool, DnsHistoryQueryParams::default()).await.unwrap();
        assert_eq!(response.total, 1);
        assert_eq!(response.items[0].domain, "new.com");
    }

    #[tokio::test]
    async fn history_limit_and_offset_are_clamped() {
        let (_dir, pool) = test_pool().await;
        let metrics: Vec<DnsMetric> = (0..250)
            .map(|index| {
                dns_metric(
                    index + 1,
                    &format!("host{}.com", index),
                    "A",
                    DnsOutcome::Normal,
                    100_000 + index as u64,
                    10,
                )
            })
            .collect();
        insert_dns_batch(&pool, &metrics).await.unwrap();

        let huge_limit = query_dns_history(
            &pool,
            DnsHistoryQueryParams { limit: Some(usize::MAX), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(huge_limit.items.len(), 200, "limit capped at MAX_PAGE_SIZE");

        let default_limit =
            query_dns_history(&pool, DnsHistoryQueryParams::default()).await.unwrap();
        assert_eq!(default_limit.items.len(), 20, "default page size preserved");

        let zero_limit = query_dns_history(
            &pool,
            DnsHistoryQueryParams { limit: Some(0), ..Default::default() },
        )
        .await
        .unwrap();
        assert_eq!(zero_limit.items.len(), 1, "limit=0 clamped up to 1");

        let deep_offset = query_dns_history(
            &pool,
            DnsHistoryQueryParams {
                limit: Some(10),
                offset: Some(usize::MAX),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(deep_offset.items.len(), 0, "offset capped, tail query returns empty");
    }

    fn build_history_filters_sql(params: &DnsHistoryQueryParams) -> String {
        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM dns_metrics");
        let mut has_where = false;
        push_history_filters(&mut qb, params, &mut has_where);
        qb.sql().to_string()
    }

    #[test]
    fn dns_history_filters_build_where_clauses() {
        let params = DnsHistoryQueryParams {
            start_time: Some(100_000),
            end_time: Some(200_000),
            flow_id: Some(3),
            domain: Some("example.com.".to_string()),
            src_ip: Some("10.0.0".to_string()),
            query_type: Some("A".to_string()),
            status: Some(DnsOutcome::Block),
            min_duration_ms: Some(5),
            max_duration_ms: Some(50),
            ..Default::default()
        };
        let sql = build_history_filters_sql(&params);
        assert!(sql.starts_with("SELECT * FROM dns_metrics WHERE "));
        assert!(sql.contains("report_time >= "));
        assert!(sql.contains("report_time < "));
        assert!(sql.contains("flow_id = "));
        assert!(sql.contains("domain LIKE "));
        assert!(sql.contains("src_ip LIKE "));
        assert!(sql.contains("query_type = "));
        assert!(sql.contains("status = "));
        assert!(sql.contains("duration_ms >= "));
        assert!(sql.contains("duration_ms <= "));
        assert_eq!(sql.matches(" WHERE ").count(), 1, "single WHERE keyword");
        assert_eq!(sql.matches(" AND ").count(), 8, "one AND per extra filter");
    }

    #[test]
    fn dns_history_filters_without_params_emit_no_where() {
        assert_eq!(
            build_history_filters_sql(&DnsHistoryQueryParams::default()),
            "SELECT * FROM dns_metrics"
        );
        let empty_strings = DnsHistoryQueryParams {
            domain: Some(String::new()),
            src_ip: Some(String::new()),
            query_type: Some(String::new()),
            ..Default::default()
        };
        assert_eq!(
            build_history_filters_sql(&empty_strings),
            "SELECT * FROM dns_metrics",
            "empty-string filters are skipped"
        );
    }

    #[test]
    fn dns_summary_filters_build_where_clauses() {
        let params = DnsSummaryQueryParams {
            start_time: 100_000,
            end_time: 200_000,
            flow_id: Some(3),
        };
        let mut qb = QueryBuilder::<Sqlite>::new("SELECT * FROM dns_metrics");
        let mut has_where = false;
        push_summary_filters(&mut qb, &params, &mut has_where);
        let summary_sql = qb.sql().to_string();
        assert!(summary_sql.contains("report_time >= "));
        assert!(summary_sql.contains("report_time < "));
        assert!(summary_sql.contains("flow_id = "));

        let mut range_qb = QueryBuilder::<Sqlite>::new("SELECT * FROM dns_metrics");
        let mut has_where = false;
        push_range_filters(&mut range_qb, &params, &mut has_where);
        assert_eq!(range_qb.sql(), summary_sql, "range filters share semantics");

        let mut empty_qb = QueryBuilder::<Sqlite>::new("SELECT * FROM dns_metrics");
        let mut has_where = false;
        push_summary_filters(&mut empty_qb, &DnsSummaryQueryParams::default(), &mut has_where);
        assert_eq!(empty_qb.sql(), "SELECT * FROM dns_metrics");
    }

    #[tokio::test]
    async fn cleanup_old_dns_deletes_rows_across_multiple_slices() {
        let (_dir, pool) = test_pool().await;
        let metrics = vec![
            dns_metric(1, "a.com", "A", DnsOutcome::Normal, 100_000, 10),
            dns_metric(2, "b.com", "A", DnsOutcome::Normal, 100_400, 10),
            dns_metric(3, "c.com", "A", DnsOutcome::Normal, 101_000, 10),
            dns_metric(4, "d.com", "A", DnsOutcome::Normal, 101_500, 10),
            dns_metric(5, "e.com", "A", DnsOutcome::Normal, 102_000, 10),
        ];
        insert_dns_batch(&pool, &metrics).await.unwrap();

        let deleted = cleanup_old_dns(&pool, 200_000, 10_000, 1).await.unwrap();
        assert_eq!(deleted, 5);

        let response = query_dns_history(&pool, DnsHistoryQueryParams::default()).await.unwrap();
        assert_eq!(response.total, 0, "all expired rows removed across slices");
    }

    #[tokio::test]
    async fn cleanup_old_dns_exits_early_when_budget_exhausted() {
        let (_dir, pool) = test_pool().await;
        let metrics: Vec<DnsMetric> = (0..200)
            .map(|index| {
                dns_metric(
                    index + 1,
                    &format!("h{}.com", index),
                    "A",
                    DnsOutcome::Normal,
                    100_000 + index as u64 * 100,
                    10,
                )
            })
            .collect();
        insert_dns_batch(&pool, &metrics).await.unwrap();

        let deleted = cleanup_old_dns(&pool, 1_000_000, 1, 1).await.unwrap();
        assert!(deleted < 200, "tiny budget forces early exit");

        let response = query_dns_history(&pool, DnsHistoryQueryParams::default()).await.unwrap();
        assert_eq!(response.total as u64 + deleted, 200, "remaining rows are deferred, not lost");
    }

    #[tokio::test]
    async fn cleanup_old_dns_clamps_zero_slice_window_to_one_second() {
        let (_dir, pool) = test_pool().await;
        let metrics = vec![
            dns_metric(1, "a.com", "A", DnsOutcome::Normal, 100_000, 10),
            dns_metric(2, "b.com", "A", DnsOutcome::Normal, 101_000, 10),
        ];
        insert_dns_batch(&pool, &metrics).await.unwrap();

        let deleted = cleanup_old_dns(&pool, 102_000, 10_000, 0).await.unwrap();
        assert_eq!(deleted, 2, "zero slice window falls back to 1s slices");
    }

    fn bucket_row(
        flow_id: u32,
        bucket_time: u64,
        report_time: u64,
        status: DnsOutcome,
        duration_ms: u32,
    ) -> DnsBucketRow {
        let mut counts = DnsCounters::default();
        counts.record(&dns_metric(flow_id, "example.com", "A", status, report_time, duration_ms));
        let mut latency = hdrhistogram::Histogram::<u64>::new(3).expect("create histogram");
        if matches!(status, DnsOutcome::Normal | DnsOutcome::NxDomain) {
            let _ = latency.record(duration_ms.max(1) as u64);
        }
        DnsBucketRow {
            flow_id,
            bucket_time,
            report_time,
            counts,
            latency,
            top_domains: vec![("example.com".to_string(), 1)],
            top_clients: vec![("10.0.0.1".to_string(), 1)],
            top_blocked: if status == DnsOutcome::Block {
                vec![("example.com".to_string(), 1)]
            } else {
                Vec::new()
            },
            slowest: if matches!(status, DnsOutcome::Normal | DnsOutcome::NxDomain) {
                vec![("example.com".to_string(), 1, duration_ms as u64)]
            } else {
                Vec::new()
            },
        }
    }

    #[tokio::test]
    async fn bucket_rows_roundtrip_into_parts() {
        let (_dir, pool) = test_pool().await;
        insert_dns_bucket_rows(
            &pool,
            &[
                bucket_row(1, 100_000, 100_030, DnsOutcome::Normal, 10),
                bucket_row(1, 100_000, 100_060, DnsOutcome::Block, 5),
                bucket_row(1, 101_000, 101_010, DnsOutcome::Normal, 30),
            ],
        )
        .await
        .unwrap();

        let parts = query_dns_summary_parts(&pool, 100_000, 102_000, None).await.unwrap();
        assert_eq!(parts.counts.total_queries, 3);
        assert_eq!(parts.counts.block_count, 1);
        assert_eq!(parts.counts.total_effective_queries, 2);
        assert_eq!(parts.top_domains.get("example.com"), Some(&3));
        assert_eq!(parts.top_clients.get("10.0.0.1"), Some(&3));
        assert_eq!(parts.top_blocked.get("example.com"), Some(&1));
        assert_eq!(parts.slowest.get("example.com"), Some(&(2, 40)));

        let response = parts.into_lightweight_response();
        assert_eq!(response.total_queries, 3);
        assert_eq!(response.avg_duration_ms, 20.0, "latency only from normal/nxdomain");
        assert_eq!(response.max_duration_ms, 30.0);
        assert_eq!(response.p50_duration_ms, 10.0, "hdrhistogram quantile by count position");
    }

    #[tokio::test]
    async fn bucket_parts_merge_same_aligned_bucket_rows_and_filter_flow() {
        let (_dir, pool) = test_pool().await;
        // 同一 bucket_time 多行是设计内行为(多个批次贡献同一分钟各自成行):读侧求和。
        insert_dns_bucket_rows(
            &pool,
            &[
                bucket_row(1, 100_000, 100_010, DnsOutcome::Normal, 10),
                bucket_row(1, 100_000, 100_040, DnsOutcome::Normal, 20),
                bucket_row(2, 100_000, 100_020, DnsOutcome::Normal, 40),
            ],
        )
        .await
        .unwrap();

        let all = query_dns_summary_parts(&pool, 100_000, 101_000, None).await.unwrap();
        assert_eq!(all.counts.total_queries, 3);
        assert_eq!(all.slowest.get("example.com"), Some(&(3, 70)));

        let flow_one = query_dns_summary_parts(&pool, 100_000, 101_000, Some(1)).await.unwrap();
        assert_eq!(flow_one.counts.total_queries, 2);
        assert_eq!(flow_one.avg_duration_ms(), 15.0);

        let flow_two = query_dns_summary_parts(&pool, 100_000, 101_000, Some(2)).await.unwrap();
        assert_eq!(flow_two.counts.total_queries, 1);
    }

    #[tokio::test]
    async fn bucket_duplicate_raw_key_is_ignored() {
        let (_dir, pool) = test_pool().await;
        let mut row = bucket_row(1, 100_000, 100_010, DnsOutcome::Normal, 10);
        row.top_blocked.push(("blocked.com".to_string(), 1));
        insert_dns_bucket_rows(&pool, &[row.clone()]).await.unwrap();
        insert_dns_bucket_rows(&pool, &[row]).await.unwrap();

        let parts = query_dns_summary_parts(&pool, 100_000, 101_000, None).await.unwrap();
        assert_eq!(parts.counts.total_queries, 1, "duplicate raw key dropped");
        assert_eq!(parts.top_domains.get("example.com"), Some(&1));
    }

    #[tokio::test]
    async fn cleanup_old_dns_buckets_deletes_across_all_tables() {
        let (_dir, pool) = test_pool().await;
        insert_dns_bucket_rows(
            &pool,
            &[
                bucket_row(1, 100_000, 100_010, DnsOutcome::Normal, 10),
                bucket_row(1, 200_000, 200_010, DnsOutcome::Normal, 10),
            ],
        )
        .await
        .unwrap();

        cleanup_old_dns_buckets(&pool, 150_000, 10_000, 60).await.unwrap();

        let expired = query_dns_summary_parts(&pool, 0, 150_000, None).await.unwrap();
        assert_eq!(expired.counts.total_queries, 0, "expired buckets removed");
        assert!(expired.top_domains.is_empty(), "top rows removed too");
        assert!(expired.slowest.is_empty(), "slowest rows removed too");

        let kept = query_dns_summary_parts(&pool, 150_000, 300_000, None).await.unwrap();
        assert_eq!(kept.counts.total_queries, 1);
    }

    #[tokio::test]
    async fn cleanup_old_dns_buckets_exits_early_when_budget_exhausted() {
        let (_dir, pool) = test_pool().await;
        // 每行独立落在一个 60s 分片内:预算耗尽时整片删除原子完成,但后续分片被推迟。
        let rows: Vec<DnsBucketRow> = (0..200)
            .map(|index| {
                let bucket_time = 100_000 + index as u64 * 60_000;
                bucket_row(1, bucket_time, bucket_time + 10, DnsOutcome::Normal, 10)
            })
            .collect();
        insert_dns_bucket_rows(&pool, &rows).await.unwrap();

        cleanup_old_dns_buckets(&pool, 10_000_000, 1, 60).await.unwrap();

        let remaining = query_dns_summary_parts(&pool, 0, 10_000_000, None).await.unwrap();
        assert!(
            remaining.counts.total_queries < 200,
            "tiny budget forces early exit; rows are deferred, not lost"
        );
    }
}
