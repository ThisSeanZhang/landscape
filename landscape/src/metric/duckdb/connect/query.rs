use duckdb::{params, Connection};
use landscape_common::metric::connect::{
    AggregateGroupBy, ConnectAggregatePoint, ConnectAggregateQueryParams, ConnectKey,
    ConnectMetricPoint, MetricResolution,
};

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

pub fn query_connection_aggregates(
    conn: &Connection,
    params: ConnectAggregateQueryParams,
) -> Vec<ConnectAggregatePoint> {
    let group_by = params.group_by.unwrap_or_default();
    let group_col = match group_by {
        AggregateGroupBy::SrcIp => "src_ip",
        AggregateGroupBy::DstPort => "CAST(dst_port AS VARCHAR)",
    };

    let mut conditions: Vec<String> = Vec::new();

    if params.start_time.is_some() {
        conditions.push("report_time >= ?".into());
    }
    if params.end_time.is_some() {
        conditions.push("report_time < ?".into());
    }
    if params.src_ip.is_some() {
        conditions.push("src_ip = ?".into());
    }
    if params.l4_proto.is_some() {
        conditions.push("l4_proto = ?".into());
    }
    if params.dst_port.is_some() {
        conditions.push("dst_port = ?".into());
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let limit = params.limit.unwrap_or(100).min(1000);

    let sql = format!(
        "SELECT {group_col} AS group_key,
                SUM(ingress_bytes) AS ingress_bytes,
                SUM(ingress_packets) AS ingress_packets,
                SUM(egress_bytes) AS egress_bytes,
                SUM(egress_packets) AS egress_packets,
                SUM(conn_count) AS conn_count
         FROM conn_aggregates_1h
         {where_clause}
         GROUP BY group_key
         ORDER BY (SUM(ingress_bytes) + SUM(egress_bytes)) DESC
         LIMIT ?"
    );

    let mut stmt = match conn.prepare(&sql) {
        Ok(stmt) => stmt,
        Err(error) => {
            tracing::error!("failed to prepare query_connection_aggregates: {}", error);
            return Vec::new();
        }
    };

    let mut bind_params: Vec<Box<dyn duckdb::ToSql>> = Vec::new();
    if let Some(start) = params.start_time {
        bind_params.push(Box::new(start as i64));
    }
    if let Some(end) = params.end_time {
        bind_params.push(Box::new(end as i64));
    }
    if let Some(ref src_ip) = params.src_ip {
        bind_params.push(Box::new(src_ip.clone()));
    }
    if let Some(proto) = params.l4_proto {
        bind_params.push(Box::new(proto as i64));
    }
    if let Some(port) = params.dst_port {
        bind_params.push(Box::new(port as i64));
    }
    bind_params.push(Box::new(limit as i64));

    let param_refs: Vec<&dyn duckdb::ToSql> = bind_params.iter().map(|b| b.as_ref()).collect();

    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(ConnectAggregatePoint {
            group_key: row.get(0)?,
            ingress_bytes: row.get::<_, i64>(1)? as u64,
            ingress_packets: row.get::<_, i64>(2)? as u64,
            egress_bytes: row.get::<_, i64>(3)? as u64,
            egress_packets: row.get::<_, i64>(4)? as u64,
            conn_count: row.get::<_, i64>(5)? as u64,
        })
    });

    match rows {
        Ok(rows) => rows.filter_map(Result::ok).collect(),
        Err(error) => {
            tracing::error!("failed to execute query_connection_aggregates: {}", error);
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metric::duckdb::connect::schema::{
        create_metrics_table, upsert_aggregate_bucket_values, AggregateBucketWrite,
    };
    use duckdb::Connection;

    fn seed_aggregates(conn: &Connection) {
        create_metrics_table(conn).unwrap();
        for (ip, port, ib) in
            [("192.168.1.10", 443, 1000u64), ("192.168.1.10", 80, 500), ("192.168.1.20", 443, 2000)]
        {
            upsert_aggregate_bucket_values(
                conn,
                &AggregateBucketWrite {
                    report_time: 3_600_000,
                    src_ip: ip.to_string(),
                    l4_proto: 6,
                    dst_port: port,
                    ingress_bytes: ib,
                    ingress_packets: 10,
                    egress_bytes: ib / 2,
                    egress_packets: 5,
                    conn_count: 1,
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn query_aggregates_group_by_src_ip() {
        let conn = Connection::open_in_memory().unwrap();
        seed_aggregates(&conn);

        let results = query_connection_aggregates(
            &conn,
            ConnectAggregateQueryParams {
                group_by: Some(AggregateGroupBy::SrcIp),
                ..Default::default()
            },
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].group_key, "192.168.1.20");
        assert_eq!(results[0].ingress_bytes, 2000);
        assert_eq!(results[1].group_key, "192.168.1.10");
        assert_eq!(results[1].ingress_bytes, 1500);
    }

    #[test]
    fn query_aggregates_group_by_dst_port() {
        let conn = Connection::open_in_memory().unwrap();
        seed_aggregates(&conn);

        let results = query_connection_aggregates(
            &conn,
            ConnectAggregateQueryParams {
                group_by: Some(AggregateGroupBy::DstPort),
                ..Default::default()
            },
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].group_key, "443");
        assert_eq!(results[0].ingress_bytes, 3000);
    }

    #[test]
    fn query_aggregates_with_src_ip_filter() {
        let conn = Connection::open_in_memory().unwrap();
        seed_aggregates(&conn);

        let results = query_connection_aggregates(
            &conn,
            ConnectAggregateQueryParams {
                group_by: Some(AggregateGroupBy::DstPort),
                src_ip: Some("192.168.1.10".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].ingress_bytes, 1000);
        assert_eq!(results[0].group_key, "443");
    }

    #[test]
    fn query_aggregates_respects_limit() {
        let conn = Connection::open_in_memory().unwrap();
        seed_aggregates(&conn);

        let results = query_connection_aggregates(
            &conn,
            ConnectAggregateQueryParams {
                group_by: Some(AggregateGroupBy::SrcIp),
                limit: Some(1),
                ..Default::default()
            },
        );
        assert_eq!(results.len(), 1);
    }
}
