use duckdb::Connection;
use landscape_common::metric::connect::SortOrder;
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSortKey, DnsStatEntry, DnsSummaryQueryParams, DnsSummaryResponse,
};

pub fn create_dns_table(conn: &Connection, schema: &str) -> duckdb::Result<()> {
    let prefix = if schema.is_empty() { "".to_string() } else { format!("{}.", schema) };
    let sql = format!(
        "
        CREATE TABLE IF NOT EXISTS {}dns_metrics (
            flow_id INTEGER,
            domain TEXT,
            query_type TEXT,
            response_code TEXT,
            report_time BIGINT,
            duration_ms INTEGER,
            src_ip TEXT,
            answers TEXT,
            status TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_dns_report_time ON {}dns_metrics (report_time);
        CREATE INDEX IF NOT EXISTS idx_dns_domain ON {}dns_metrics (domain);
        CREATE INDEX IF NOT EXISTS idx_dns_src_ip ON {}dns_metrics (src_ip);
        CREATE INDEX IF NOT EXISTS idx_dns_status ON {}dns_metrics (status);
    ",
        prefix, prefix, prefix, prefix, prefix
    );

    conn.execute_batch(&sql)
}

pub fn query_dns_history(
    conn: &Connection,
    mut params: DnsHistoryQueryParams,
) -> DnsHistoryResponse {
    let mut where_clauses = Vec::new();
    let mut sql_params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();

    if let Some(start) = params.start_time {
        where_clauses.push(format!("report_time >= ?"));
        sql_params.push(Box::new(start as i64));
    }
    if let Some(end) = params.end_time {
        where_clauses.push(format!("report_time <= ?"));
        sql_params.push(Box::new(end as i64));
    }
    if let Some(domain) = params.domain.as_mut() {
        if !domain.is_empty() {
            // 同样处理一下末尾的点，确保匹配
            if domain.ends_with('.') && domain.len() > 1 {
                domain.pop();
            }
            where_clauses.push(format!("domain LIKE ?"));
            sql_params.push(Box::new(format!("%{}%", domain)));
        }
    }
    if let Some(ip) = params.src_ip {
        if !ip.is_empty() {
            where_clauses.push(format!("src_ip LIKE ?"));
            sql_params.push(Box::new(format!("%{}%", ip)));
        }
    }
    if let Some(flow_id) = params.flow_id {
        where_clauses.push(format!("flow_id = ?"));
        sql_params.push(Box::new(flow_id as i64));
    }
    if let Some(qtype) = params.query_type {
        if !qtype.is_empty() {
            where_clauses.push(format!("query_type = ?"));
            sql_params.push(Box::new(qtype));
        }
    }
    if let Some(status) = params.status {
        let status_str = serde_json::to_string(&status).unwrap_or_default();
        where_clauses.push(format!("status = ?"));
        sql_params.push(Box::new(status_str));
    }
    if let Some(min_dur) = params.min_duration_ms {
        where_clauses.push(format!("duration_ms >= ?"));
        sql_params.push(Box::new(min_dur as i64));
    }
    if let Some(max_dur) = params.max_duration_ms {
        where_clauses.push(format!("duration_ms <= ?"));
        sql_params.push(Box::new(max_dur as i64));
    }

    let where_stmt = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // 1. 获取总数
    let count_stmt_str = format!("SELECT COUNT(*) FROM dns_metrics {}", where_stmt);
    let total: usize = {
        match conn.prepare(&count_stmt_str) {
            Ok(mut stmt) => {
                let param_refs: Vec<&dyn duckdb::ToSql> =
                    sql_params.iter().map(|p| p.as_ref()).collect();
                stmt.query_row(&param_refs[..], |row| row.get(0)).unwrap_or(0)
            }
            Err(e) => {
                tracing::error!(
                    "Failed to prepare DNS count SQL: {}, error: {}",
                    count_stmt_str,
                    e
                );
                0
            }
        }
    };

    // 2. 排序
    let sort_col = match params.sort_key.unwrap_or_default() {
        DnsSortKey::Time => "report_time",
        DnsSortKey::Domain => "domain",
        DnsSortKey::Duration => "duration_ms",
    };
    let sort_order_str = match params.sort_order.unwrap_or_default() {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    };

    // 3. 分页
    let limit_val = params.limit.unwrap_or(20);
    let offset_val = params.offset.unwrap_or(0);

    // 添加次要排序字段确保排序稳定性
    let order_by = if sort_col == "report_time" {
        format!("{} {}", sort_col, sort_order_str)
    } else {
        format!("{} {}, report_time DESC", sort_col, sort_order_str)
    };

    let query_stmt_str = format!(
        "
        SELECT 
            flow_id, domain, query_type, response_code, report_time, duration_ms, src_ip, answers, status
        FROM dns_metrics
        {}
        ORDER BY {}
        LIMIT {} OFFSET {}
    ",
        where_stmt, order_by, limit_val, offset_val
    );

    let mut stmt = match conn.prepare(&query_stmt_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare DNS SQL: {}, error: {}", query_stmt_str, e);
            return DnsHistoryResponse { items: Vec::new(), total };
        }
    };

    let param_refs: Vec<&dyn duckdb::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(&param_refs[..], |row| {
        let answers_str: String = row.get(7)?;
        let answers: Vec<String> = serde_json::from_str(&answers_str).unwrap_or_default();
        Ok(DnsMetric {
            flow_id: row.get::<_, i64>(0)? as u32,
            domain: row.get(1)?,
            query_type: row.get(2)?,
            response_code: row.get(3)?,
            report_time: row.get::<_, i64>(4)? as u64,
            duration_ms: row.get::<_, i64>(5)? as u32,
            src_ip: row.get::<_, String>(6)?.parse().unwrap_or("0.0.0.0".parse().unwrap()),
            answers,
            status: serde_json::from_str(
                &row.get::<_, String>(8).unwrap_or_else(|_| "\"normal\"".to_string()),
            )
            .unwrap_or_default(),
        })
    });

    let items = match rows {
        Ok(r) => r.filter_map(Result::ok).collect(),
        Err(e) => {
            tracing::error!("Failed to execute DNS query: {}", e);
            Vec::new()
        }
    };

    DnsHistoryResponse { items, total }
}

pub fn cleanup_old_dns_metrics(conn: &Connection, cutoff: u64) {
    let _ = conn
        .execute("DELETE FROM dns_metrics WHERE report_time < ?1", duckdb::params![cutoff as i64]);
}

pub fn query_dns_summary(conn: &Connection, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
    let mut where_clauses = Vec::new();
    let mut sql_params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();

    {
        where_clauses.push(format!("report_time >= ?"));
        sql_params.push(Box::new(params.start_time as i64));
    }
    {
        where_clauses.push(format!("report_time <= ?"));
        sql_params.push(Box::new(params.end_time as i64));
    }
    if let Some(flow_id) = params.flow_id {
        where_clauses.push(format!("flow_id = ?"));
        sql_params.push(Box::new(flow_id as i64));
    }

    let where_stmt = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let param_refs: Vec<&dyn duckdb::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();

    // 1. 基本统计
    //有效查询定义：非拦截且非错误的查询
    let stats_sql = format!(
        "SELECT 
            COUNT(*),
            COUNT(CASE WHEN status = '\"hit\"' THEN 1 END),
            -- 有效查询总数 (排除 block, filter 和 error)
            COUNT(CASE WHEN status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            
            -- V4 统计
            COUNT(CASE WHEN query_type = 'A' AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'A' AND status = '\"hit\"' THEN 1 END),
            
            -- V6 统计
            COUNT(CASE WHEN query_type = 'AAAA' AND status NOT IN ('\"block\"', '\"filter\"', '\"error\"') THEN 1 END),
            COUNT(CASE WHEN query_type = 'AAAA' AND status = '\"hit\"' THEN 1 END),
            
            -- 其他统计
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

    let (
        total_queries,
        cache_hit_count,
        total_effective_queries,
        total_v4,
        hit_count_v4,
        total_v6,
        hit_count_v6,
        total_other,
        hit_count_other,
        block_count,
        filter_count,
        nxdomain_count,
        error_count,
        avg_duration_ms,
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms,
        max_duration_ms,
    ) = conn
        .query_row(&stats_sql, &param_refs[..], |row| {
            Ok((
                row.get::<_, i64>(0)? as usize,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, i64>(3)? as usize,
                row.get::<_, i64>(4)? as usize,
                row.get::<_, i64>(5)? as usize,
                row.get::<_, i64>(6)? as usize,
                row.get::<_, i64>(7)? as usize,
                row.get::<_, i64>(8)? as usize,
                row.get::<_, i64>(9)? as usize,
                row.get::<_, i64>(10)? as usize,
                row.get::<_, i64>(11)? as usize,
                row.get::<_, i64>(12)? as usize,
                row.get::<_, Option<f64>>(13)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(14)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(15)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(16)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(17)?.unwrap_or(0.0),
            ))
        })
        .unwrap_or((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0));

    // 2. Top Clients
    let top_clients_sql = format!(
        "SELECT src_ip, COUNT(*) as c FROM dns_metrics {} GROUP BY src_ip ORDER BY c DESC LIMIT 10",
        where_stmt
    );
    let top_clients = match conn.prepare(&top_clients_sql) {
        Ok(mut stmt) => stmt
            .query_map(&param_refs[..], |row| {
                Ok(DnsStatEntry {
                    name: row.get(0)?,
                    count: row.get::<_, i64>(1)? as usize,
                    value: None,
                })
            })
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_else(|e| {
                tracing::error!("Failed to execute top_clients query: {}", e);
                Vec::new()
            }),
        Err(e) => {
            tracing::error!("Failed to prepare top_clients SQL: {}, error: {}", top_clients_sql, e);
            Vec::new()
        }
    };

    // 3. Top Domains
    let top_domains_sql = format!(
        "SELECT domain, COUNT(*) as c FROM dns_metrics {} GROUP BY domain ORDER BY c DESC LIMIT 10",
        where_stmt
    );
    let top_domains = match conn.prepare(&top_domains_sql) {
        Ok(mut stmt) => stmt
            .query_map(&param_refs[..], |row| {
                Ok(DnsStatEntry {
                    name: row.get(0)?,
                    count: row.get::<_, i64>(1)? as usize,
                    value: None,
                })
            })
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_else(|e| {
                tracing::error!("Failed to execute top_domains query: {}", e);
                Vec::new()
            }),
        Err(e) => {
            tracing::error!("Failed to prepare top_domains SQL: {}, error: {}", top_domains_sql, e);
            Vec::new()
        }
    };

    // 4. Top Blocked
    let top_blocked_sql = format!(
        "SELECT domain, COUNT(*) as c FROM dns_metrics {} AND status = '\"block\"' GROUP BY domain ORDER BY c DESC LIMIT 10",
        if where_stmt.is_empty() { "WHERE 1=1" } else { &where_stmt }
    );
    let top_blocked = match conn.prepare(&top_blocked_sql) {
        Ok(mut stmt) => stmt
            .query_map(&param_refs[..], |row| {
                Ok(DnsStatEntry {
                    name: row.get(0)?,
                    count: row.get::<_, i64>(1)? as usize,
                    value: None,
                })
            })
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_else(|e| {
                tracing::error!("Failed to execute top_blocked query: {}", e);
                Vec::new()
            }),
        Err(e) => {
            tracing::error!("Failed to prepare top_blocked SQL: {}, error: {}", top_blocked_sql, e);
            Vec::new()
        }
    };

    // 5. Slowest Domains
    let slowest_sql = format!(
        "SELECT domain, AVG(duration_ms) as avg_d, COUNT(*) as c FROM dns_metrics {} GROUP BY domain HAVING c > 2 ORDER BY avg_d DESC LIMIT 10",
        where_stmt
    );
    let slowest_domains = match conn.prepare(&slowest_sql) {
        Ok(mut stmt) => stmt
            .query_map(&param_refs[..], |row| {
                Ok(DnsStatEntry {
                    name: row.get(0)?,
                    count: row.get::<_, i64>(2)? as usize,
                    value: Some(row.get(1)?),
                })
            })
            .map(|r| r.filter_map(Result::ok).collect())
            .unwrap_or_else(|e| {
                tracing::error!("Failed to execute slowest_domains query: {}", e);
                Vec::new()
            }),
        Err(e) => {
            tracing::error!("Failed to prepare slowest_domains SQL: {}, error: {}", slowest_sql, e);
            Vec::new()
        }
    };

    DnsSummaryResponse {
        total_queries,
        total_effective_queries,
        cache_hit_count,
        hit_count_v4,
        hit_count_v6,
        hit_count_other,
        total_v4,
        total_v6,
        total_other,
        block_count,
        filter_count,
        nxdomain_count,
        error_count,
        avg_duration_ms,
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms,
        max_duration_ms,
        top_clients,
        top_domains,
        top_blocked,
        slowest_domains,
    }
}

pub fn query_dns_lightweight_summary(
    conn: &Connection,
    params: DnsSummaryQueryParams,
) -> DnsLightweightSummaryResponse {
    let mut where_clauses = Vec::new();
    let mut sql_params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();

    where_clauses.push(format!("report_time >= ?"));
    sql_params.push(Box::new(params.start_time as i64));

    where_clauses.push(format!("report_time <= ?"));
    sql_params.push(Box::new(params.end_time as i64));

    if let Some(flow_id) = params.flow_id {
        where_clauses.push(format!("flow_id = ?"));
        sql_params.push(Box::new(flow_id as i64));
    }

    let where_stmt = format!("WHERE {}", where_clauses.join(" AND "));

    let param_refs: Vec<&dyn duckdb::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();

    // 1. 基本统计
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

    let (
        total_queries,
        cache_hit_count,
        total_effective_queries,
        total_v4,
        hit_count_v4,
        total_v6,
        hit_count_v6,
        total_other,
        hit_count_other,
        block_count,
        filter_count,
        nxdomain_count,
        error_count,
        avg_duration_ms,
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms,
        max_duration_ms,
    ) = conn
        .query_row(&stats_sql, &param_refs[..], |row| {
            Ok((
                row.get::<_, i64>(0)? as usize,
                row.get::<_, i64>(1)? as usize,
                row.get::<_, i64>(2)? as usize,
                row.get::<_, i64>(3)? as usize,
                row.get::<_, i64>(4)? as usize,
                row.get::<_, i64>(5)? as usize,
                row.get::<_, i64>(6)? as usize,
                row.get::<_, i64>(7)? as usize,
                row.get::<_, i64>(8)? as usize,
                row.get::<_, i64>(9)? as usize,
                row.get::<_, i64>(10)? as usize,
                row.get::<_, i64>(11)? as usize,
                row.get::<_, i64>(12)? as usize,
                row.get::<_, Option<f64>>(13)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(14)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(15)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(16)?.unwrap_or(0.0),
                row.get::<_, Option<f64>>(17)?.unwrap_or(0.0),
            ))
        })
        .unwrap_or((0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0));

    DnsLightweightSummaryResponse {
        total_queries,
        total_effective_queries,
        cache_hit_count,
        hit_count_v4,
        hit_count_v6,
        hit_count_other,
        total_v4,
        total_v6,
        total_other,
        block_count,
        filter_count,
        nxdomain_count,
        error_count,
        avg_duration_ms,
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms,
        max_duration_ms,
    }
}
