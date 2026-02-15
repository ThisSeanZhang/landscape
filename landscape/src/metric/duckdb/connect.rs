use duckdb::Statement;
use duckdb::{params, Connection};
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey, ConnectMetric,
    ConnectMetricPoint, ConnectSortKey, MetricResolution, SortOrder,
};
use std::path::PathBuf;

pub const SUMMARY_INSERT_SQL: &str = "
    INSERT OR REPLACE INTO conn_summaries (
        create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto, flow_id, trace_id,
        last_report_time, total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts, status, create_time_ms
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
";

pub const METRICS_1M_INSERT_SQL: &str = "
    INSERT OR REPLACE INTO conn_metrics_1m (
        create_time, cpu_id, report_time, 
        ingress_bytes, ingress_packets, egress_bytes, egress_packets, status, create_time_ms
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
";

pub const METRICS_1H_INSERT_SQL: &str = "
    INSERT OR REPLACE INTO conn_metrics_1h (
        create_time, cpu_id, report_time, 
        ingress_bytes, ingress_packets, egress_bytes, egress_packets, status, create_time_ms
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
";

pub const METRICS_1D_INSERT_SQL: &str = "
    INSERT OR REPLACE INTO conn_metrics_1d (
        create_time, cpu_id, report_time, 
        ingress_bytes, ingress_packets, egress_bytes, egress_packets, status, create_time_ms
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
";

pub const LIVE_METRIC_INSERT_SQL: &str = "
    INSERT INTO conn_realtime (
        create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto, flow_id, trace_id,
        ingress_bytes, egress_bytes, ingress_packets, egress_packets, ingress_bps, egress_bps, ingress_pps, egress_pps,
        last_report_time, status, create_time_ms
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)
    ON CONFLICT (create_time, cpu_id) DO UPDATE SET
        ingress_bps = CASE 
            WHEN (EXCLUDED.last_report_time - last_report_time) > 0 
            THEN (EXCLUDED.ingress_bytes - ingress_bytes) * 8000 / (EXCLUDED.last_report_time - last_report_time)
            ELSE ingress_bps 
        END,
        egress_bps = CASE 
            WHEN (EXCLUDED.last_report_time - last_report_time) > 0 
            THEN (EXCLUDED.egress_bytes - egress_bytes) * 8000 / (EXCLUDED.last_report_time - last_report_time)
            ELSE egress_bps 
        END,
        ingress_pps = CASE 
            WHEN (EXCLUDED.last_report_time - last_report_time) > 0 
            THEN (EXCLUDED.ingress_packets - ingress_packets) * 1000 / (EXCLUDED.last_report_time - last_report_time)
            ELSE ingress_pps 
        END,
        egress_pps = CASE 
            WHEN (EXCLUDED.last_report_time - last_report_time) > 0 
            THEN (EXCLUDED.egress_packets - egress_packets) * 1000 / (EXCLUDED.last_report_time - last_report_time)
            ELSE egress_pps 
        END,
        ingress_bytes = EXCLUDED.ingress_bytes,
        egress_bytes = EXCLUDED.egress_bytes,
        ingress_packets = EXCLUDED.ingress_packets,
        egress_packets = EXCLUDED.egress_packets,
        last_report_time = EXCLUDED.last_report_time,
        status = EXCLUDED.status
";

pub fn update_summary_by_metric(
    stmt: &mut Statement,
    metric: &ConnectMetric,
) -> duckdb::Result<usize> {
    let key = &metric.key;
    let event_type_val: u8 = metric.status.clone().into();

    stmt.execute(params![
        key.create_time as i64,
        key.cpu_id as i64,
        metric.src_ip.to_string(),
        metric.dst_ip.to_string(),
        metric.src_port as i64,
        metric.dst_port as i64,
        metric.l4_proto as i64,
        metric.l3_proto as i64,
        metric.flow_id as i64,
        metric.trace_id as i64,
        metric.report_time as i64,
        metric.ingress_bytes as i64,
        metric.egress_bytes as i64,
        metric.ingress_packets as i64,
        metric.egress_packets as i64,
        event_type_val as i64,
        metric.create_time_ms as i64,
    ])
}

pub fn update_live_metric(stmt: &mut Statement, metric: &ConnectMetric) -> duckdb::Result<usize> {
    let key = &metric.key;
    let event_type_val: u8 = metric.status.clone().into();

    stmt.execute(params![
        key.create_time as i64,
        key.cpu_id as i64,
        metric.src_ip.to_string(),
        metric.dst_ip.to_string(),
        metric.src_port as i64,
        metric.dst_port as i64,
        metric.l4_proto as i64,
        metric.l3_proto as i64,
        metric.flow_id as i64,
        metric.trace_id as i64,
        metric.ingress_bytes as i64,
        metric.egress_bytes as i64,
        metric.ingress_packets as i64,
        metric.egress_packets as i64,
        0i64,
        0i64,
        0i64,
        0i64,
        metric.report_time as i64,
        event_type_val as i64,
        metric.create_time_ms as i64,
    ])
}

pub fn create_summaries_table(conn: &Connection, schema: &str) {
    let prefix = if schema.is_empty() { "".to_string() } else { format!("{}.", schema) };
    let sql = format!(
        "
        CREATE TABLE IF NOT EXISTS {}conn_summaries (
            create_time UBIGINT,
            cpu_id INTEGER,
            src_ip VARCHAR,
            dst_ip VARCHAR,
            src_port INTEGER,
            dst_port INTEGER,
            l4_proto INTEGER,
            l3_proto INTEGER,
            flow_id INTEGER,
            trace_id INTEGER,
            last_report_time UBIGINT,
            total_ingress_bytes UBIGINT,
            total_egress_bytes UBIGINT,
            total_ingress_pkts UBIGINT,
            total_egress_pkts UBIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id)
        );
        CREATE INDEX IF NOT EXISTS idx_conn_summaries_time ON {}conn_summaries (last_report_time);
    ",
        prefix, prefix
    );

    conn.execute_batch(&sql).expect("Failed to create summaries table");
}

pub fn create_metrics_table(conn: &Connection, schema: &str) -> duckdb::Result<()> {
    let prefix = if schema.is_empty() { "".to_string() } else { format!("{}.", schema) };
    let sql = format!(
        "
        CREATE TABLE IF NOT EXISTS {}conn_metrics_1m (
            create_time UBIGINT,
            cpu_id INTEGER,
            report_time BIGINT,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id, report_time)
        );

        CREATE TABLE IF NOT EXISTS {}conn_metrics_1h (
            create_time UBIGINT,
            cpu_id INTEGER,
            report_time BIGINT,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id, report_time)
        );

        CREATE TABLE IF NOT EXISTS {}conn_metrics_1d (
            create_time UBIGINT,
            cpu_id INTEGER,
            report_time BIGINT,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id, report_time)
        );

        CREATE TABLE IF NOT EXISTS {}global_stats (
            total_ingress_bytes BIGINT,
            total_egress_bytes BIGINT,
            total_ingress_pkts BIGINT,
            total_egress_pkts BIGINT,
            total_connect_count BIGINT,
            last_calculate_time UBIGINT
        );
    ",
        prefix, prefix, prefix, prefix
    );

    conn.execute_batch(&sql)
}

pub fn create_live_tables(conn: &Connection) -> duckdb::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS conn_realtime (
            create_time UBIGINT,
            cpu_id INTEGER,
            src_ip VARCHAR,
            dst_ip VARCHAR,
            src_port INTEGER,
            dst_port INTEGER,
            l4_proto INTEGER,
            l3_proto INTEGER,
            flow_id INTEGER,
            trace_id INTEGER,
            ingress_bytes UBIGINT,
            egress_bytes UBIGINT,
            ingress_packets UBIGINT,
            egress_packets UBIGINT,
            ingress_bps UBIGINT,
            egress_bps UBIGINT,
            ingress_pps UBIGINT,
            egress_pps UBIGINT,
            last_report_time UBIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id)
        );

        CREATE TABLE IF NOT EXISTS conn_metrics (
            create_time UBIGINT,
            cpu_id INTEGER,
            report_time BIGINT,
            ingress_bytes BIGINT,
            ingress_packets BIGINT,
            egress_bytes BIGINT,
            egress_packets BIGINT,
            status INTEGER,
            create_time_ms UBIGINT
        );

        CREATE TABLE IF NOT EXISTS conn_summaries (
            create_time UBIGINT,
            cpu_id INTEGER,
            src_ip VARCHAR,
            dst_ip VARCHAR,
            src_port INTEGER,
            dst_port INTEGER,
            l4_proto INTEGER,
            l3_proto INTEGER,
            flow_id INTEGER,
            trace_id INTEGER,
            last_report_time UBIGINT,
            total_ingress_bytes UBIGINT,
            total_egress_bytes UBIGINT,
            total_ingress_pkts UBIGINT,
            total_egress_pkts UBIGINT,
            status INTEGER,
            create_time_ms UBIGINT,
            PRIMARY KEY (create_time, cpu_id)
        );
        ",
    )
}

pub fn query_metric_by_key(
    conn: &Connection,
    key: &ConnectKey,
    resolution: MetricResolution,
    _history_db_path: Option<&PathBuf>,
) -> Vec<ConnectMetricPoint> {
    let table = match resolution {
        MetricResolution::Second => "conn_metrics",
        MetricResolution::Minute => "history.conn_metrics_1m",
        MetricResolution::Hour => "history.conn_metrics_1h",
        MetricResolution::Day => "history.conn_metrics_1d",
    };

    let stmt_str = format!(
        "
        SELECT 
            report_time,
            ingress_bytes,
            ingress_packets,
            egress_bytes,
            egress_packets,
            status
        FROM {}
        WHERE create_time = ?1 AND cpu_id = ?2
        ORDER BY report_time
    ",
        table
    );

    let mut stmt = match conn.prepare(&stmt_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                "Failed to prepare query_metric_by_key SQL: {}, error: {}",
                stmt_str,
                e
            );
            return Vec::new();
        }
    };

    let rows = stmt.query_map(params![key.create_time as i64, key.cpu_id as i64,], |row| {
        Ok(ConnectMetricPoint {
            report_time: row.get(0)?,
            ingress_bytes: row.get(1)?,
            ingress_packets: row.get(2)?,
            egress_bytes: row.get(3)?,
            egress_packets: row.get(4)?,
            status: row.get::<_, u8>(5)?.into(),
        })
    });

    match rows {
        Ok(r) => r.filter_map(Result::ok).collect(),
        Err(e) => {
            tracing::error!("Failed to execute query_metric_by_key: {}", e);
            Vec::new()
        }
    }
}

pub fn query_historical_summaries_complex(
    conn: &Connection,
    params: ConnectHistoryQueryParams,
    history_db_path: Option<&PathBuf>,
) -> Vec<ConnectHistoryStatus> {
    let now = landscape_common::utils::time::get_current_time_ms().unwrap_or_default();

    let table_name = if history_db_path.is_some() {
        "history.conn_summaries".to_string()
    } else {
        "conn_summaries".to_string()
    };

    if let Some(start) = params.start_time {
        tracing::debug!(
            "History Query - StartTime: {}, Now: {}, Diff: {}ms",
            start,
            now,
            now.saturating_sub(start)
        );
    }

    let mut where_clauses = Vec::new();
    if let Some(start) = params.start_time {
        where_clauses.push(format!("last_report_time >= {}", start));
    }
    if let Some(end) = params.end_time {
        where_clauses.push(format!("last_report_time <= {}", end));
    }
    if let Some(ip) = params.src_ip {
        if !ip.is_empty() {
            where_clauses.push(format!("src_ip LIKE '%{}%'", ip));
        }
    }
    if let Some(ip) = params.dst_ip {
        if !ip.is_empty() {
            where_clauses.push(format!("dst_ip LIKE '%{}%'", ip));
        }
    }
    if let Some(p) = params.port_start {
        where_clauses.push(format!("src_port = {}", p));
    }
    if let Some(p) = params.port_end {
        where_clauses.push(format!("dst_port = {}", p));
    }
    if let Some(p) = params.l3_proto {
        where_clauses.push(format!("l3_proto = {}", p));
    }
    if let Some(p) = params.l4_proto {
        where_clauses.push(format!("l4_proto = {}", p));
    }
    if let Some(p) = params.flow_id {
        where_clauses.push(format!("flow_id = {}", p));
    }

    if let Some(s) = params.status {
        where_clauses.push(format!("status = {}", s));
    }

    let where_stmt = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let sort_col = match params.sort_key.unwrap_or_default() {
        ConnectSortKey::Port => "src_port",
        ConnectSortKey::Ingress => "total_ingress_bytes",
        ConnectSortKey::Egress => "total_egress_bytes",
        ConnectSortKey::Time => "last_report_time",
        ConnectSortKey::Duration => "(last_report_time - create_time_ms)",
    };
    let sort_order_str = match params.sort_order.unwrap_or_default() {
        SortOrder::Asc => "ASC",
        SortOrder::Desc => "DESC",
    };

    let limit_clause =
        if let Some(l) = params.limit { format!("LIMIT {}", l) } else { String::new() };

    let stmt_str = format!("
        SELECT 
            create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto, flow_id, trace_id,
            total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts, last_report_time, status, create_time_ms
        FROM {}
        {}
        ORDER BY {} {}
        {}
    ", table_name, where_stmt, sort_col, sort_order_str, limit_clause);

    let mut stmt = match conn.prepare(&stmt_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare SQL: {}, error: {}", stmt_str, e);
            return Vec::new();
        }
    };

    let rows = stmt.query_map([], |row| {
        let create_time_ms: u64 = row.get::<_, i64>(16)? as u64;
        let key = ConnectKey {
            create_time: row.get::<_, i64>(0)? as u64,
            cpu_id: row.get::<_, i64>(1)? as u32,
        };
        Ok(ConnectHistoryStatus {
            key,
            src_ip: row.get::<_, String>(2)?.parse().unwrap_or("0.0.0.0".parse().unwrap()),
            dst_ip: row.get::<_, String>(3)?.parse().unwrap_or("0.0.0.0".parse().unwrap()),
            src_port: row.get::<_, i64>(4)? as u16,
            dst_port: row.get::<_, i64>(5)? as u16,
            l4_proto: row.get::<_, i64>(6)? as u8,
            l3_proto: row.get::<_, i64>(7)? as u8,
            flow_id: row.get::<_, i64>(8)? as u8,
            trace_id: row.get::<_, i64>(9)? as u8,
            total_ingress_bytes: row.get::<_, i64>(10)? as u64,
            total_egress_bytes: row.get::<_, i64>(11)? as u64,
            total_ingress_pkts: row.get::<_, i64>(12)? as u64,
            total_egress_pkts: row.get::<_, i64>(13)? as u64,
            last_report_time: row.get::<_, i64>(14)? as u64,
            status: row.get::<_, i64>(15)? as u8,
            create_time_ms,
        })
    });

    match rows {
        Ok(r) => r.filter_map(Result::ok).collect(),
        Err(e) => {
            tracing::error!("Failed to execute query: {}", e);
            Vec::new()
        }
    }
}

pub fn current_active_connect_keys(conn: &Connection) -> Vec<ConnectKey> {
    let stmt = "
        SELECT create_time, cpu_id
        FROM conn_summaries
        WHERE status = 1
    ";

    let mut stmt = match conn.prepare(stmt) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare SQL for active connects: {}", e);
            return Vec::new();
        }
    };

    let rows = stmt.query_map([], |row| {
        Ok(ConnectKey {
            create_time: row.get::<_, i64>(0)? as u64,
            cpu_id: row.get::<_, i64>(1)? as u32,
        })
    });

    match rows {
        Ok(r) => r.filter_map(Result::ok).collect(),
        Err(e) => {
            tracing::error!("Failed to execute active connects query: {}", e);
            Vec::new()
        }
    }
}

pub fn query_global_stats(conn: &Connection) -> ConnectGlobalStats {
    let stmt = "
        SELECT 
            total_ingress_bytes, 
            total_egress_bytes, 
            total_ingress_pkts, 
            total_egress_pkts, 
            total_connect_count,
            last_calculate_time
        FROM global_stats
        LIMIT 1
    ";

    let mut stmt = match conn.prepare(stmt) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare SQL for global stats: {}", e);
            return ConnectGlobalStats::default();
        }
    };

    let res = stmt.query_row([], |row| {
        Ok(ConnectGlobalStats {
            total_ingress_bytes: row.get::<_, i64>(0)? as u64,
            total_egress_bytes: row.get::<_, i64>(1)? as u64,
            total_ingress_pkts: row.get::<_, i64>(2)? as u64,
            total_egress_pkts: row.get::<_, i64>(3)? as u64,
            total_connect_count: row.get::<_, i64>(4)? as u64,
            last_calculate_time: row.get::<_, i64>(5)? as u64,
        })
    });

    res.unwrap_or_default()
}

pub fn aggregate_global_stats(conn: &Connection) -> duckdb::Result<()> {
    conn.execute_batch(
        "
        DELETE FROM global_stats;
        INSERT INTO global_stats 
        SELECT 
            SUM(max_ingress_bytes),
            SUM(max_egress_bytes),
            SUM(max_ingress_pkts),
            SUM(max_egress_pkts),
            COUNT(*),
            EXTRACT(EPOCH FROM now()) * 1000
        FROM (
            SELECT 
                MAX(ingress_bytes) as max_ingress_bytes,
                MAX(egress_bytes) as max_egress_bytes,
                MAX(ingress_packets) as max_ingress_pkts,
                MAX(egress_packets) as max_egress_pkts
            FROM conn_metrics_1d
            GROUP BY create_time, cpu_id
        );
    ",
    )
}

pub fn perform_batch_rollup(conn: &Connection, _history_db_path: &PathBuf) -> duckdb::Result<()> {
    let sql_1m = "
        INSERT OR REPLACE INTO history.conn_metrics_1m (
            create_time, cpu_id, report_time, 
            ingress_bytes, ingress_packets, egress_bytes, egress_packets, status, create_time_ms
        )
        SELECT 
            create_time, cpu_id, (report_time // 60000) * 60000 as rt, 
            MAX(ingress_bytes), MAX(ingress_packets), MAX(egress_bytes), MAX(egress_packets), MAX(status), MAX(create_time_ms)
        FROM conn_metrics 
        GROUP BY 1, 2, 3;";

    let sql_1h = "
        INSERT OR REPLACE INTO history.conn_metrics_1h (
            create_time, cpu_id, report_time, 
            ingress_bytes, ingress_packets, egress_bytes, egress_packets, status, create_time_ms
        )
        SELECT 
            create_time, cpu_id, (report_time // 3600000) * 3600000 as rt, 
            MAX(ingress_bytes), MAX(ingress_packets), MAX(egress_bytes), MAX(egress_packets), MAX(status), MAX(create_time_ms)
        FROM conn_metrics 
        GROUP BY 1, 2, 3;";

    let sql_1d = "
        INSERT OR REPLACE INTO history.conn_metrics_1d (
            create_time, cpu_id, report_time, 
            ingress_bytes, ingress_packets, egress_bytes, egress_packets, status, create_time_ms
        )
        SELECT 
            create_time, cpu_id, (report_time // 86400000) * 86400000 as rt, 
            MAX(ingress_bytes), MAX(ingress_packets), MAX(egress_bytes), MAX(egress_packets), MAX(status), MAX(create_time_ms)
        FROM conn_metrics 
        GROUP BY 1, 2, 3;";

    let sql_summary = "
        INSERT OR REPLACE INTO history.conn_summaries (
            create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, 
            l4_proto, l3_proto, flow_id, trace_id,
            last_report_time, total_ingress_bytes, total_egress_bytes, 
            total_ingress_pkts, total_egress_pkts, status, create_time_ms
        )
        SELECT 
            create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, 
            l4_proto, l3_proto, flow_id, trace_id,
            last_report_time, total_ingress_bytes, total_egress_bytes, 
            total_ingress_pkts, total_egress_pkts, status, create_time_ms
        FROM main.conn_summaries;";

    let r_1m = conn.execute(sql_1m, [])?;
    let r_1h = conn.execute(sql_1h, [])?;
    let r_1d = conn.execute(sql_1d, [])?;
    let r_summary = conn.execute(sql_summary, [])?;

    // 显式刷新磁盘库，确保数据对其他连接（如查询连接）立即可见
    if let Err(e) = conn.execute_batch("CHECKPOINT history;") {
        tracing::error!("Failed to checkpoint history database: {}", e);
    }

    tracing::info!("Batch rollup: 1m:{} 1h:{} 1d:{} sum:{}", r_1m, r_1h, r_1d, r_summary);

    Ok(())
}

pub fn collect_and_cleanup_old_metrics(
    conn: &Connection,
    cutoff_raw: u64,
    cutoff_1m: u64,
    cutoff_1h: u64,
    cutoff_1d: u64,
    _history_db_path: &PathBuf,
) -> Box<Vec<ConnectMetric>> {
    // Fetch expired metric records
    let stmt = "
        SELECT 
            s.create_time, s.cpu_id, s.src_ip, s.dst_ip, s.src_port, s.dst_port, s.l4_proto, s.l3_proto, s.flow_id, s.trace_id,
            m.report_time, m.ingress_bytes, m.ingress_packets, m.egress_bytes, m.egress_packets, m.status, s.create_time_ms
        FROM conn_metrics m
        JOIN history.conn_summaries s ON m.create_time = s.create_time AND m.cpu_id = s.cpu_id
        WHERE m.report_time < ?1
    ";

    let mut stmt = match conn.prepare(stmt) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare cleanup SELECT SQL: {}, error: {}", stmt, e);
            return Box::new(Vec::new());
        }
    };

    let metrics_iter = stmt.query_map([cutoff_raw as i64], |row| {
        let key = ConnectKey {
            create_time: row.get::<_, i64>(0)? as u64,
            cpu_id: row.get::<_, i64>(1)? as u32,
        };

        Ok(ConnectMetric {
            key,
            src_ip: row.get::<_, String>(2)?.parse().unwrap_or("0.0.0.0".parse().unwrap()),
            dst_ip: row.get::<_, String>(3)?.parse().unwrap_or("0.0.0.0".parse().unwrap()),
            src_port: row.get::<_, i64>(4)? as u16,
            dst_port: row.get::<_, i64>(5)? as u16,
            l4_proto: row.get::<_, i64>(6)? as u8,
            l3_proto: row.get::<_, i64>(7)? as u8,
            flow_id: row.get::<_, i64>(8)? as u8,
            trace_id: row.get::<_, i64>(9)? as u8,
            report_time: row.get(10)?,
            create_time_ms: row.get(16)?,
            ingress_bytes: row.get(11)?,
            ingress_packets: row.get(12)?,
            egress_bytes: row.get(13)?,
            egress_packets: row.get(14)?,
            status: row.get::<_, u8>(15)?.into(),
        })
    });

    let metrics = match metrics_iter {
        Ok(r) => r.filter_map(Result::ok).collect::<Vec<_>>(),
        Err(e) => {
            tracing::error!("Failed to execute cleanup SELECT: {}", e);
            Vec::new()
        }
    };

    // Delete expired metric records
    let deleted_metrics = conn
        .execute("DELETE FROM conn_metrics WHERE report_time < ?1", params![cutoff_raw as i64])
        .unwrap_or_else(|e| {
            tracing::error!("Failed to delete expired raw metrics: {}", e);
            0
        });

    let _ = conn
        .execute(
            "DELETE FROM history.conn_metrics_1m WHERE report_time < ?1",
            params![cutoff_1m as i64],
        )
        .map_err(|e| tracing::error!("Failed to delete expired 1m metrics: {}", e));

    let _ = conn
        .execute(
            "DELETE FROM history.conn_metrics_1h WHERE report_time < ?1",
            params![cutoff_1h as i64],
        )
        .map_err(|e| tracing::error!("Failed to delete expired 1h metrics: {}", e));

    let _ = conn
        .execute(
            "DELETE FROM history.conn_metrics_1d WHERE report_time < ?1",
            params![cutoff_1d as i64],
        )
        .map_err(|e| tracing::error!("Failed to delete expired 1d metrics: {}", e));

    let size = match conn.prepare("SELECT COUNT(*) FROM conn_metrics") {
        Ok(mut stmt) => stmt.query_row([], |row| row.get::<_, usize>(0)).unwrap_or(0),
        Err(e) => {
            tracing::error!("Failed to prepare count query: {}", e);
            0
        }
    };

    tracing::info!(
        "Cleanup complete: deleted {} metric records from memory, remaining in memory: {}",
        deleted_metrics,
        size
    );

    let deleted_history_summaries = conn
        .execute(
            "DELETE FROM history.conn_summaries WHERE last_report_time < ?1",
            params![cutoff_1d as i64],
        )
        .unwrap_or(0);

    // Also cleanup memory summaries (more aggressively, e.g., same as raw metrics)
    let deleted_memory_summaries = conn
        .execute(
            "DELETE FROM conn_summaries WHERE last_report_time < ?1",
            params![cutoff_raw as i64],
        )
        .unwrap_or(0);

    tracing::info!(
        "Cleanup summaries complete: deleted {} history disk records, deleted {} memory cache records",
        deleted_history_summaries,
        deleted_memory_summaries
    );

    Box::new(metrics)
}

pub fn query_connection_ip_history(
    conn: &Connection,
    params: ConnectHistoryQueryParams,
    is_src: bool,
    history_db_path: Option<&PathBuf>,
) -> Vec<landscape_common::metric::connect::IpHistoryStat> {
    let table_prefix = if history_db_path.is_some() { "history." } else { "" };
    let table_name = format!("{}conn_summaries", table_prefix);

    let mut where_clauses = Vec::new();
    let col = if is_src { "src_ip" } else { "dst_ip" };
    if let Some(start) = params.start_time {
        where_clauses.push(format!("last_report_time >= {}", start));
    }
    if let Some(end) = params.end_time {
        where_clauses.push(format!("last_report_time <= {}", end));
    }
    if let Some(p) = params.flow_id {
        where_clauses.push(format!("flow_id = {}", p));
    }
    if let Some(ip) = params.src_ip {
        if !ip.is_empty() {
            where_clauses.push(format!("src_ip LIKE '%{}%'", ip));
        }
    }
    if let Some(ip) = params.dst_ip {
        if !ip.is_empty() {
            where_clauses.push(format!("dst_ip LIKE '%{}%'", ip));
        }
    }

    let where_stmt = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    let stmt_str = format!(
        "
        SELECT 
            {}, 
            SUM(total_ingress_bytes), SUM(total_egress_bytes), 
            SUM(total_ingress_pkts), SUM(total_egress_pkts), 
            COUNT(*)
        FROM {}
        {}
        GROUP BY 1
        ORDER BY 2 DESC 
        LIMIT 10
    ",
        col, table_name, where_stmt
    );

    let mut stmt = match conn.prepare(&stmt_str) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to prepare IP history SQL: {}, error: {}", stmt_str, e);
            return Vec::new();
        }
    };

    let rows = stmt.query_map([], |row| {
        Ok(landscape_common::metric::connect::IpHistoryStat {
            ip: row.get::<_, String>(0)?.parse().unwrap_or("0.0.0.0".parse().unwrap()),
            flow_id: 0,
            total_ingress_bytes: row.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
            total_egress_bytes: row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
            total_ingress_pkts: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
            total_egress_pkts: row.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64,
            connect_count: row.get::<_, i64>(5)? as u32,
        })
    });

    match rows {
        Ok(r) => r.filter_map(Result::ok).collect(),
        Err(e) => {
            tracing::error!("Failed to execute IP history query: {}", e);
            Vec::new()
        }
    }
}
