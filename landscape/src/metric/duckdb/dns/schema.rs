use duckdb::{params, Connection};

pub fn create_dns_table(conn: &Connection) -> duckdb::Result<()> {
    let sql = "
        CREATE TABLE IF NOT EXISTS dns_metrics (
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
    ";

    conn.execute_batch(sql)
}

pub fn cleanup_old_dns_metrics(conn: &Connection, cutoff: u64) -> usize {
    conn.execute("DELETE FROM dns_metrics WHERE report_time < ?1", params![cutoff as i64])
        .unwrap_or_else(|error| {
            tracing::error!("failed to cleanup old dns metrics: {}", error);
            0
        })
}
