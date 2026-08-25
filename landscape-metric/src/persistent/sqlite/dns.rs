use futures_util::StreamExt;
use landscape_common::metric::connect::SortOrder;
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSortKey, DnsStatEntry, DnsSummaryQueryParams, DnsSummaryResponse,
};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

use crate::ingest::clean_ip_string;

const LATENCY_EXCLUDE: &str = "'\"block\"', '\"filter\"', '\"error\"', '\"local\"', '\"hit\"'";

const PERCENTILE_QUANTILES: [f64; 3] = [0.50, 0.95, 0.99];

/// 历史查询单页条数上限,防止无界 LIMIT 导致慢查询/超大响应。
const MAX_PAGE_SIZE: usize = 200;
/// 历史查询翻页偏移上限。
const MAX_PAGE_OFFSET: usize = 10_000;

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

    let mut tx = pool.begin().await?;
    for metric in metrics {
        let answers_json = serde_json::to_string(&metric.answers).unwrap_or_default();
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
        .execute(tx.as_mut())
        .await?;
    }
    tx.commit().await
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
            .unwrap_or("0.0.0.0".parse().expect("valid fallback ip")),
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

pub(crate) async fn cleanup_old_dns(pool: &SqlitePool, cutoff: u64) -> Result<u64, sqlx::Error> {
    // TODO(cleanup): 单条大范围 DELETE 没有分片也没有 cleanup_time_budget_ms 预算。
    // dns_metrics 保留 7 天原始行,高 QPS 下表大时该删除会长时间独占写锁,
    // 可能超过写入侧 busy_timeout(5s)导致 DNS 批次被丢弃;后续应仿照
    // connect 桶表 cleanup_old_buckets/delete_table_in_slices 的分片 + 预算模式改造。
    sqlx::query("DELETE FROM dns_metrics WHERE report_time < ?1")
        .bind(cutoff as i64)
        .execute(pool)
        .await
        .map(|result| result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistent::sqlite::open_dns_pool;
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
        let pool = open_dns_pool(&dir.path().join("dns.db")).await.unwrap();
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

        let deleted = cleanup_old_dns(&pool, 150_000).await.unwrap();
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
}
