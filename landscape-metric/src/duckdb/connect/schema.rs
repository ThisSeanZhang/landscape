use duckdb::Connection;

/// Number of columns in one `conn_metrics_*` bucket row. Shared with the
/// cold store so the Rust row layout cannot drift from the SQL column list.
pub(crate) const BUCKET_COLUMNS: usize = 10;
/// Number of columns in one `iface_metrics_5s` bucket row; see
/// [`BUCKET_COLUMNS`].
pub(crate) const IFACE_BUCKET_COLUMNS: usize = 7;

fn multi_row_values(row_count: usize, column_count: usize) -> String {
    (0..row_count)
        .map(|row| {
            let base = row * column_count;
            (1..=column_count)
                .map(|column| format!("?{}", base + column))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .map(|row| format!("({row})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Multi-row bucket upsert.
///
/// DuckDB executes prepared statements row by row, so a loop of single-row
/// upserts is interpreted once per row. Batching the rows into one
/// `INSERT ... SELECT` from a `VALUES` list keeps the whole batch on the
/// vectorized execution path. The `VALUES` list must stay wrapped in a
/// subquery: a flat multi-row `INSERT ... VALUES ... ON CONFLICT` fails to
/// bind once the row count grows past a few hundred rows.
pub fn upsert_metric_bucket_values_sql(table: &str, row_count: usize) -> String {
    let values = multi_row_values(row_count, BUCKET_COLUMNS);
    format!(
        "
        INSERT INTO {table} (
            create_time, cpu_id, report_time, ifindex,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            status, create_time_ms
        )
        SELECT create_time, cpu_id, report_time, ifindex,
               ingress_bytes, ingress_packets, egress_bytes, egress_packets,
               status, create_time_ms
        FROM (VALUES {values}) AS batch(
            create_time, cpu_id, report_time, ifindex,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            status, create_time_ms
        )
        ON CONFLICT (create_time, cpu_id, report_time) DO UPDATE SET
            ifindex = CASE
                WHEN EXCLUDED.create_time_ms >= {table}.create_time_ms THEN EXCLUDED.ifindex
                ELSE {table}.ifindex
            END,
            ingress_bytes = GREATEST({table}.ingress_bytes, EXCLUDED.ingress_bytes),
            ingress_packets = GREATEST({table}.ingress_packets, EXCLUDED.ingress_packets),
            egress_bytes = GREATEST({table}.egress_bytes, EXCLUDED.egress_bytes),
            egress_packets = GREATEST({table}.egress_packets, EXCLUDED.egress_packets),
            status = GREATEST({table}.status, EXCLUDED.status),
            create_time_ms = GREATEST({table}.create_time_ms, EXCLUDED.create_time_ms)
    "
    )
}

/// Multi-row iface bucket upsert; see [`upsert_metric_bucket_values_sql`].
pub fn upsert_iface_metric_bucket_values_sql(row_count: usize) -> String {
    let values = multi_row_values(row_count, IFACE_BUCKET_COLUMNS);
    format!(
        "
        INSERT INTO iface_metrics_5s (
            ifindex, report_time,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            active_conns
        )
        SELECT ifindex, report_time,
               ingress_bytes, ingress_packets, egress_bytes, egress_packets,
               active_conns
        FROM (VALUES {values}) AS batch(
            ifindex, report_time,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            active_conns
        )
        ON CONFLICT (ifindex, report_time) DO UPDATE SET
            ingress_bytes = iface_metrics_5s.ingress_bytes + EXCLUDED.ingress_bytes,
            ingress_packets = iface_metrics_5s.ingress_packets + EXCLUDED.ingress_packets,
            egress_bytes = iface_metrics_5s.egress_bytes + EXCLUDED.egress_bytes,
            egress_packets = iface_metrics_5s.egress_packets + EXCLUDED.egress_packets,
            active_conns = GREATEST(iface_metrics_5s.active_conns, EXCLUDED.active_conns)
    "
    )
}

pub fn create_metrics_table(conn: &Connection) -> duckdb::Result<()> {
    let sql = "
        CREATE TABLE IF NOT EXISTS conn_metrics_1m (
            create_time UBIGINT,
            cpu_id INTEGER,
            report_time BIGINT,
            ifindex INTEGER,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id, report_time)
        );

        CREATE TABLE IF NOT EXISTS conn_metrics_1h (
            create_time UBIGINT,
            cpu_id INTEGER,
            report_time BIGINT,
            ifindex INTEGER,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id, report_time)
        );

        CREATE TABLE IF NOT EXISTS conn_metrics_1d (
            create_time UBIGINT,
            cpu_id INTEGER,
            report_time BIGINT,
            ifindex INTEGER,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id, report_time)
        );

        CREATE TABLE IF NOT EXISTS iface_metrics_5s (
            ifindex INTEGER,
            report_time BIGINT,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            active_conns INTEGER,
            PRIMARY KEY (ifindex, report_time)
        );
    ";

    conn.execute_batch(sql)
}
