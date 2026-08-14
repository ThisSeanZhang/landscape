use duckdb::{params, Connection};

#[allow(clippy::too_many_arguments)]
pub fn upsert_metric_bucket_values(
    conn: &Connection,
    table: &str,
    create_time: u64,
    cpu_id: u32,
    report_time: u64,
    ingress_bytes: u64,
    ingress_packets: u64,
    egress_bytes: u64,
    egress_packets: u64,
    status: u8,
    create_time_ms: u64,
    ifindex: u32,
) -> duckdb::Result<usize> {
    let sql = format!(
        "
        INSERT INTO {table} (
            create_time, cpu_id, report_time, ifindex,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            status, create_time_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
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
    );

    conn.execute(
        &sql,
        params![
            create_time as i64,
            cpu_id as i64,
            report_time as i64,
            ifindex as i64,
            ingress_bytes as i64,
            ingress_packets as i64,
            egress_bytes as i64,
            egress_packets as i64,
            status as i64,
            create_time_ms as i64,
        ],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn upsert_iface_metric_bucket_values(
    conn: &Connection,
    ifindex: u32,
    report_time: u64,
    ingress_bytes: u64,
    ingress_packets: u64,
    egress_bytes: u64,
    egress_packets: u64,
    active_conns: u32,
) -> duckdb::Result<usize> {
    conn.execute(
        "
        INSERT INTO iface_metrics_5s (
            ifindex, report_time,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets,
            active_conns
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT (ifindex, report_time) DO UPDATE SET
            ingress_bytes = iface_metrics_5s.ingress_bytes + EXCLUDED.ingress_bytes,
            ingress_packets = iface_metrics_5s.ingress_packets + EXCLUDED.ingress_packets,
            egress_bytes = iface_metrics_5s.egress_bytes + EXCLUDED.egress_bytes,
            egress_packets = iface_metrics_5s.egress_packets + EXCLUDED.egress_packets,
            active_conns = GREATEST(iface_metrics_5s.active_conns, EXCLUDED.active_conns)
        ",
        params![
            ifindex as i64,
            report_time as i64,
            ingress_bytes as i64,
            ingress_packets as i64,
            egress_bytes as i64,
            egress_packets as i64,
            active_conns as i64,
        ],
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
