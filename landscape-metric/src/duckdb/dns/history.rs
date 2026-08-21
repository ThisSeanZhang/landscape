use duckdb::Connection;
use landscape_common::metric::connect::SortOrder;
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsMetric, DnsSortKey,
};

use super::DnsWhereBuilder;

pub fn query_dns_history(conn: &Connection, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
    let builder = DnsWhereBuilder::from_history_params(&params);
    let where_stmt = builder.where_stmt();
    let param_refs = builder.param_refs();

    let count_stmt_str = format!("SELECT COUNT(*) FROM dns_metrics {}", where_stmt);
    let total: usize = match conn.prepare(&count_stmt_str) {
        Ok(mut stmt) => stmt.query_row(&param_refs[..], |row| row.get(0)).unwrap_or(0),
        Err(error) => {
            tracing::error!(
                "Failed to prepare DNS count SQL: {}, error: {}",
                count_stmt_str,
                error
            );
            0
        }
    };

    let sort_col = match params.sort_key.unwrap_or_default() {
        DnsSortKey::Time => "report_time",
        DnsSortKey::Domain => "domain",
        DnsSortKey::Duration => "duration_ms",
    };
    let sort_order = match params.sort_order.unwrap_or_default() {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    };
    let limit = params.limit.unwrap_or(20);
    let offset = params.offset.unwrap_or(0);
    let order_by = if sort_col == "report_time" {
        format!("{} {}", sort_col, sort_order)
    } else {
        format!("{} {}, report_time DESC", sort_col, sort_order)
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
        where_stmt, order_by, limit, offset
    );

    let mut stmt = match conn.prepare(&query_stmt_str) {
        Ok(stmt) => stmt,
        Err(error) => {
            tracing::error!("Failed to prepare DNS SQL: {}, error: {}", query_stmt_str, error);
            return DnsHistoryResponse { items: Vec::new(), total };
        }
    };

    let rows = stmt.query_map(&param_refs[..], |row| {
        let answers: Vec<String> =
            serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default();
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
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(error) => {
            tracing::error!("Failed to execute DNS query: {}", error);
            Vec::new()
        }
    };

    DnsHistoryResponse { items, total }
}
