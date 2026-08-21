use duckdb::Connection;
use landscape_common::metric::dns::{
    DnsLightweightSummaryResponse, DnsStatEntry, DnsSummaryQueryParams, DnsSummaryResponse,
};

use super::DnsWhereBuilder;

#[derive(Default)]
struct DnsSummaryBaseStats {
    total_queries: usize,
    cache_hit_count: usize,
    total_effective_queries: usize,
    total_v4: usize,
    hit_count_v4: usize,
    total_v6: usize,
    hit_count_v6: usize,
    total_other: usize,
    hit_count_other: usize,
    block_count: usize,
    filter_count: usize,
    nxdomain_count: usize,
    error_count: usize,
    avg_duration_ms: f64,
    p50_duration_ms: f64,
    p95_duration_ms: f64,
    p99_duration_ms: f64,
    max_duration_ms: f64,
}

fn query_base_stats(
    conn: &Connection,
    where_stmt: &str,
    param_refs: &[&dyn duckdb::ToSql],
) -> DnsSummaryBaseStats {
    let stats_sql = format!(
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
            AVG(CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"', '\"local\"', '\"hit\"') THEN duration_ms END),
            percentile_cont(0.5) WITHIN GROUP (ORDER BY CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"', '\"local\"', '\"hit\"') THEN duration_ms END),
            percentile_cont(0.95) WITHIN GROUP (ORDER BY CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"', '\"local\"', '\"hit\"') THEN duration_ms END),
            percentile_cont(0.99) WITHIN GROUP (ORDER BY CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"', '\"local\"', '\"hit\"') THEN duration_ms END),
            MAX(CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"', '\"local\"', '\"hit\"') THEN duration_ms END)
        FROM dns_metrics {}",
        where_stmt
    );

    conn.query_row(&stats_sql, param_refs, |row| {
        Ok(DnsSummaryBaseStats {
            total_queries: row.get::<_, i64>(0)? as usize,
            cache_hit_count: row.get::<_, i64>(1)? as usize,
            total_effective_queries: row.get::<_, i64>(2)? as usize,
            total_v4: row.get::<_, i64>(3)? as usize,
            hit_count_v4: row.get::<_, i64>(4)? as usize,
            total_v6: row.get::<_, i64>(5)? as usize,
            hit_count_v6: row.get::<_, i64>(6)? as usize,
            total_other: row.get::<_, i64>(7)? as usize,
            hit_count_other: row.get::<_, i64>(8)? as usize,
            block_count: row.get::<_, i64>(9)? as usize,
            filter_count: row.get::<_, i64>(10)? as usize,
            nxdomain_count: row.get::<_, i64>(11)? as usize,
            error_count: row.get::<_, i64>(12)? as usize,
            avg_duration_ms: row.get::<_, Option<f64>>(13)?.unwrap_or(0.0),
            p50_duration_ms: row.get::<_, Option<f64>>(14)?.unwrap_or(0.0),
            p95_duration_ms: row.get::<_, Option<f64>>(15)?.unwrap_or(0.0),
            p99_duration_ms: row.get::<_, Option<f64>>(16)?.unwrap_or(0.0),
            max_duration_ms: row.get::<_, Option<f64>>(17)?.unwrap_or(0.0),
        })
    })
    .unwrap_or_default()
}

fn query_top_entries(
    conn: &Connection,
    sql: &str,
    param_refs: &[&dyn duckdb::ToSql],
    parse_value: bool,
) -> Vec<DnsStatEntry> {
    match conn.prepare(sql) {
        Ok(mut stmt) => stmt
            .query_map(param_refs, |row| {
                Ok(DnsStatEntry {
                    name: row.get(0)?,
                    count: row.get::<_, i64>(if parse_value { 2 } else { 1 })? as usize,
                    value: if parse_value { Some(row.get(1)?) } else { None },
                })
            })
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_else(|error| {
                tracing::error!("Failed to execute DNS summary query: {}", error);
                Vec::new()
            }),
        Err(error) => {
            tracing::error!("Failed to prepare DNS summary SQL: {}, error: {}", sql, error);
            Vec::new()
        }
    }
}

pub fn query_dns_summary(conn: &Connection, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
    let builder = DnsWhereBuilder::from_summary_params(&params);
    let where_stmt = builder.where_stmt();
    let where_stmt_blocked = builder.where_stmt_with_extra("status = '\"block\"'");
    let param_refs = builder.param_refs();
    let stats = query_base_stats(conn, &where_stmt, &param_refs);

    let top_clients_sql = format!(
        "SELECT src_ip, COUNT(*) as c FROM dns_metrics {} GROUP BY src_ip ORDER BY c DESC LIMIT 10",
        where_stmt
    );
    let top_domains_sql = format!(
        "SELECT domain, COUNT(*) as c FROM dns_metrics {} GROUP BY domain ORDER BY c DESC LIMIT 10",
        where_stmt
    );
    let top_blocked_sql = format!(
        "SELECT domain, COUNT(*) as c FROM dns_metrics {} GROUP BY domain ORDER BY c DESC LIMIT 10",
        where_stmt_blocked
    );
    let slowest_sql = format!(
        "SELECT domain, AVG(duration_ms) as avg_d, COUNT(*) as c FROM dns_metrics {} GROUP BY domain HAVING c > 2 ORDER BY avg_d DESC LIMIT 10",
        where_stmt
    );

    DnsSummaryResponse {
        total_queries: stats.total_queries,
        total_effective_queries: stats.total_effective_queries,
        cache_hit_count: stats.cache_hit_count,
        hit_count_v4: stats.hit_count_v4,
        hit_count_v6: stats.hit_count_v6,
        hit_count_other: stats.hit_count_other,
        total_v4: stats.total_v4,
        total_v6: stats.total_v6,
        total_other: stats.total_other,
        block_count: stats.block_count,
        filter_count: stats.filter_count,
        nxdomain_count: stats.nxdomain_count,
        error_count: stats.error_count,
        avg_duration_ms: stats.avg_duration_ms,
        p50_duration_ms: stats.p50_duration_ms,
        p95_duration_ms: stats.p95_duration_ms,
        p99_duration_ms: stats.p99_duration_ms,
        max_duration_ms: stats.max_duration_ms,
        top_clients: query_top_entries(conn, &top_clients_sql, &param_refs, false),
        top_domains: query_top_entries(conn, &top_domains_sql, &param_refs, false),
        top_blocked: query_top_entries(conn, &top_blocked_sql, &param_refs, false),
        slowest_domains: query_top_entries(conn, &slowest_sql, &param_refs, true),
    }
}

pub fn query_dns_lightweight_summary(
    conn: &Connection,
    params: DnsSummaryQueryParams,
) -> DnsLightweightSummaryResponse {
    let builder = DnsWhereBuilder::from_summary_params(&params);
    let where_stmt = builder.where_stmt();
    let param_refs = builder.param_refs();
    let stats = query_base_stats(conn, &where_stmt, &param_refs);

    DnsLightweightSummaryResponse {
        total_queries: stats.total_queries,
        total_effective_queries: stats.total_effective_queries,
        cache_hit_count: stats.cache_hit_count,
        hit_count_v4: stats.hit_count_v4,
        hit_count_v6: stats.hit_count_v6,
        hit_count_other: stats.hit_count_other,
        total_v4: stats.total_v4,
        total_v6: stats.total_v6,
        total_other: stats.total_other,
        block_count: stats.block_count,
        filter_count: stats.filter_count,
        nxdomain_count: stats.nxdomain_count,
        error_count: stats.error_count,
        avg_duration_ms: stats.avg_duration_ms,
        p50_duration_ms: stats.p50_duration_ms,
        p95_duration_ms: stats.p95_duration_ms,
        p99_duration_ms: stats.p99_duration_ms,
        max_duration_ms: stats.max_duration_ms,
    }
}
