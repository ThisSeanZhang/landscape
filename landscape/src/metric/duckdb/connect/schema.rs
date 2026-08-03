use duckdb::{params, Connection};

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

        CREATE TABLE IF NOT EXISTS conn_aggregates_1h (
            report_time BIGINT,
            src_ip TEXT,
            l4_proto INTEGER,
            dst_port INTEGER,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            conn_count BIGINT,
            PRIMARY KEY (report_time, src_ip, l4_proto, dst_port)
        );
    ";

    conn.execute_batch(sql)
}

/// One row of the bounded-cardinality aggregate tier, ready to persist.
#[derive(Debug, Clone, Default)]
pub struct AggregateBucketWrite {
    pub report_time: u64,
    pub src_ip: String,
    pub l4_proto: u8,
    pub dst_port: u16,
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
    pub conn_count: u64,
}

/// Fold one aggregate bucket into conn_aggregates_1h.
///
/// Unlike the per-connection cold tables, this key is shared by many connections,
/// so the counters must ADD. GREATEST would silently keep only the largest
/// contributor and drop the rest of the traffic.
pub fn upsert_aggregate_bucket_values(
    conn: &Connection,
    w: &AggregateBucketWrite,
) -> duckdb::Result<usize> {
    conn.execute(
        "
        INSERT INTO conn_aggregates_1h (
            report_time, src_ip, l4_proto, dst_port,
            ingress_bytes, ingress_packets, egress_bytes, egress_packets, conn_count
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT (report_time, src_ip, l4_proto, dst_port) DO UPDATE SET
            ingress_bytes   = conn_aggregates_1h.ingress_bytes   + EXCLUDED.ingress_bytes,
            ingress_packets = conn_aggregates_1h.ingress_packets + EXCLUDED.ingress_packets,
            egress_bytes    = conn_aggregates_1h.egress_bytes    + EXCLUDED.egress_bytes,
            egress_packets  = conn_aggregates_1h.egress_packets  + EXCLUDED.egress_packets,
            conn_count      = conn_aggregates_1h.conn_count      + EXCLUDED.conn_count
        ",
        params![
            w.report_time as i64,
            w.src_ip.as_str(),
            w.l4_proto as i64,
            w.dst_port as i64,
            w.ingress_bytes as i64,
            w.ingress_packets as i64,
            w.egress_bytes as i64,
            w.egress_packets as i64,
            w.conn_count as i64,
        ],
    )
}

#[cfg(test)]
mod aggregate_tests {
    use super::*;

    fn write(report_time: u64, ib: u64, eb: u64, cc: u64) -> AggregateBucketWrite {
        AggregateBucketWrite {
            report_time,
            src_ip: "192.168.100.20".to_string(),
            l4_proto: 6,
            dst_port: 443,
            ingress_bytes: ib,
            ingress_packets: 1,
            egress_bytes: eb,
            egress_packets: 1,
            conn_count: cc,
        }
    }

    #[test]
    fn accumulates_across_connections() {
        let conn = Connection::open_in_memory().unwrap();
        create_metrics_table(&conn).unwrap();
        upsert_aggregate_bucket_values(&conn, &write(3_600_000, 100, 200, 1)).unwrap();
        upsert_aggregate_bucket_values(&conn, &write(3_600_000, 300, 400, 1)).unwrap();
        let row: (i64, i64, i64) = conn
            .query_row(
                "SELECT ingress_bytes, egress_bytes, conn_count FROM conn_aggregates_1h
                 WHERE report_time = ?1",
                params![3_600_000i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, (400, 600, 2), "cross-connection counters must add, not max");
    }
}
