use duckdb::{params, Connection};
use landscape_common::metric::connect::{ConnectKey, ConnectMetricPoint, MetricResolution};

pub fn query_metric_by_key(
    conn: &Connection,
    key: &ConnectKey,
    resolution: MetricResolution,
) -> Vec<ConnectMetricPoint> {
    let table = match resolution {
        MetricResolution::Second => return Vec::new(),
        MetricResolution::Minute => "conn_metrics_1m",
        MetricResolution::Hour => "conn_metrics_1h",
        MetricResolution::Day => "conn_metrics_1d",
    };

    let stmt_str = format!(
        "
        SELECT
            report_time,
            ifindex,
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
        Ok(stmt) => stmt,
        Err(error) => {
            tracing::error!(
                "failed to prepare query_metric_by_key SQL: {}, error: {}",
                stmt_str,
                error
            );
            return Vec::new();
        }
    };

    let rows = stmt.query_map(params![key.create_time as i64, key.cpu_id as i64], |row| {
        Ok(ConnectMetricPoint {
            report_time: row.get(0)?,
            ingress_bytes: row.get(2)?,
            ingress_packets: row.get(3)?,
            egress_bytes: row.get(4)?,
            egress_packets: row.get(5)?,
            status: row.get::<_, u8>(6)?.into(),
        })
    });

    match rows {
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(error) => {
            tracing::error!("failed to execute query_metric_by_key: {}", error);
            Vec::new()
        }
    }
}
