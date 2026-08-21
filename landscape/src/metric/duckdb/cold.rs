use duckdb::{params_from_iter, DuckdbConnectionManager};
use landscape_common::config::MetricRuntimeConfig;
use landscape_common::metric::dns::DnsMetric;
use landscape_core::time::get_current_time_ms;
use std::collections::HashMap;
use std::time::Instant;

use crate::metric::cold::{BucketPersistStats, ColdCleanupStats, ColdStore, DnsPersistStats};
use crate::metric::ingest::{
    clean_ip_string, BucketKind, BucketWrite, IfaceBucketWrite, MS_PER_DAY,
};

use super::connect::{cleanup, schema as connect_schema};
use super::dns::schema as dns_schema;

const DNS_METRIC_COLUMNS: usize = 9;
/// Rows per multi-row bucket upsert statement. Bounds the statement size and
/// the prepared-statement parameter count while keeping DuckDB on its
/// vectorized execution path.
const BUCKET_UPSERT_CHUNK_ROWS: usize = 1024;

/// DuckDB-backed cold history store.
///
/// All writes are batch-oriented: bucket upserts are grouped per table,
/// folded by primary key, and flushed as multi-row `INSERT ... SELECT`
/// statements inside a single transaction, and DNS metrics are inserted as
/// one multi-row statement per batch.
pub(crate) struct DuckdbColdStore {
    pool: r2d2::Pool<DuckdbConnectionManager>,
}

impl DuckdbColdStore {
    pub(crate) fn new(pool: r2d2::Pool<DuckdbConnectionManager>) -> Self {
        Self { pool }
    }
}

/// Column layout of one merged `conn_metrics_*` row. The primary key
/// occupies the first three columns (`create_time`, `cpu_id`,
/// `report_time`); the constants below index the merged payload columns.
mod conn_columns {
    pub(crate) const IFINDEX: usize = 3;
    pub(crate) const INGRESS_BYTES: usize = 4;
    pub(crate) const INGRESS_PACKETS: usize = 5;
    pub(crate) const EGRESS_BYTES: usize = 6;
    pub(crate) const EGRESS_PACKETS: usize = 7;
    pub(crate) const STATUS: usize = 8;
    pub(crate) const CREATE_TIME_MS: usize = 9;
}

/// Column layout of one merged `iface_metrics_5s` row. The primary key
/// occupies the first two columns (`ifindex`, `report_time`).
mod iface_columns {
    pub(crate) const INGRESS_BYTES: usize = 2;
    pub(crate) const INGRESS_PACKETS: usize = 3;
    pub(crate) const EGRESS_BYTES: usize = 4;
    pub(crate) const EGRESS_PACKETS: usize = 5;
    pub(crate) const ACTIVE_CONNS: usize = 6;
}

/// Collapse bucket rows sharing a primary key into one row, applying exactly
/// the merge the single-row upsert applied per incoming row: counters and
/// `create_time_ms` keep the maximum, and the `ifindex` comes from the latest
/// `create_time_ms` seen (arrival order breaks ties).
///
/// A vectorized multi-row `INSERT ... ON CONFLICT` must not receive the same
/// key twice within one statement: DuckDB resolves in-statement duplicate
/// keys differently from the row-by-row merge, so duplicates are folded here
/// before the statement is built.
fn aggregate_conn_bucket_rows(rows: &[&BucketWrite]) -> Vec<[i64; connect_schema::BUCKET_COLUMNS]> {
    let mut slot_by_key: HashMap<(u64, u32, u64), usize> = HashMap::with_capacity(rows.len());
    let mut merged: Vec<[i64; connect_schema::BUCKET_COLUMNS]> = Vec::with_capacity(rows.len());
    for bucket in rows {
        let status: u8 = bucket.metric.status.clone().into();
        let row = [
            bucket.metric.key.create_time as i64,
            bucket.metric.key.cpu_id as i64,
            bucket.bucket_report_time as i64,
            bucket.metric.ifindex as i64,
            bucket.metric.ingress_bytes as i64,
            bucket.metric.ingress_packets as i64,
            bucket.metric.egress_bytes as i64,
            bucket.metric.egress_packets as i64,
            status as i64,
            bucket.metric.create_time_ms as i64,
        ];
        let key =
            (bucket.metric.key.create_time, bucket.metric.key.cpu_id, bucket.bucket_report_time);
        match slot_by_key.get(&key) {
            Some(&slot) => {
                let existing = &mut merged[slot];
                if row[conn_columns::CREATE_TIME_MS] >= existing[conn_columns::CREATE_TIME_MS] {
                    existing[conn_columns::IFINDEX] = row[conn_columns::IFINDEX];
                }
                for column in [
                    conn_columns::INGRESS_BYTES,
                    conn_columns::INGRESS_PACKETS,
                    conn_columns::EGRESS_BYTES,
                    conn_columns::EGRESS_PACKETS,
                    conn_columns::STATUS,
                    conn_columns::CREATE_TIME_MS,
                ] {
                    existing[column] = existing[column].max(row[column]);
                }
            }
            None => {
                slot_by_key.insert(key, merged.len());
                merged.push(row);
            }
        }
    }
    merged
}

/// Collapse iface bucket rows sharing `(ifindex, report_time)`, applying the
/// additive merge the single-row upsert applied per incoming row. Counter
/// overflows saturate instead of failing the batch; the SQL-side `+` on
/// existing table rows would error, but 5s-bucket byte/packet deltas cannot
/// realistically reach `i64::MAX`.
fn aggregate_iface_bucket_rows(
    rows: &[IfaceBucketWrite],
) -> Vec<[i64; connect_schema::IFACE_BUCKET_COLUMNS]> {
    let mut slot_by_key: HashMap<(u32, u64), usize> = HashMap::with_capacity(rows.len());
    let mut merged: Vec<[i64; connect_schema::IFACE_BUCKET_COLUMNS]> =
        Vec::with_capacity(rows.len());
    for bucket in rows {
        let row = [
            bucket.ifindex as i64,
            bucket.report_time as i64,
            bucket.ingress_bytes as i64,
            bucket.ingress_packets as i64,
            bucket.egress_bytes as i64,
            bucket.egress_packets as i64,
            bucket.active_conns as i64,
        ];
        let key = (bucket.ifindex, bucket.report_time);
        match slot_by_key.get(&key) {
            Some(&slot) => {
                let existing = &mut merged[slot];
                for column in [
                    iface_columns::INGRESS_BYTES,
                    iface_columns::INGRESS_PACKETS,
                    iface_columns::EGRESS_BYTES,
                    iface_columns::EGRESS_PACKETS,
                ] {
                    existing[column] = existing[column].saturating_add(row[column]);
                }
                existing[iface_columns::ACTIVE_CONNS] =
                    existing[iface_columns::ACTIVE_CONNS].max(row[iface_columns::ACTIVE_CONNS]);
            }
            None => {
                slot_by_key.insert(key, merged.len());
                merged.push(row);
            }
        }
    }
    merged
}

/// Execute the chunked multi-row upserts for one table, preparing (and then
/// reusing) one statement per distinct chunk length: a batch produces at
/// most the full-chunk statement plus one remainder statement.
fn execute_conn_bucket_chunks(
    tx: &duckdb::Transaction<'_>,
    table: &str,
    rows: &[[i64; connect_schema::BUCKET_COLUMNS]],
) -> Result<(), String> {
    let mut prepared_by_len: HashMap<usize, duckdb::Statement<'_>> = HashMap::new();
    for chunk in rows.chunks(BUCKET_UPSERT_CHUNK_ROWS) {
        if !prepared_by_len.contains_key(&chunk.len()) {
            let sql = connect_schema::upsert_metric_bucket_values_sql(table, chunk.len());
            let statement = tx.prepare(&sql).map_err(|error| {
                format!("failed to prepare cold bucket upsert for {}: {}", table, error)
            })?;
            prepared_by_len.insert(chunk.len(), statement);
        }
        let statement = prepared_by_len.get_mut(&chunk.len()).expect("prepared above");
        statement.execute(params_from_iter(chunk.iter().flatten().copied())).map_err(|error| {
            format!(
                "failed to write cold bucket batch of {} rows into {}: {}",
                chunk.len(),
                table,
                error
            )
        })?;
    }
    Ok(())
}

/// Iface counterpart of [`execute_conn_bucket_chunks`].
fn execute_iface_bucket_chunks(
    tx: &duckdb::Transaction<'_>,
    rows: &[[i64; connect_schema::IFACE_BUCKET_COLUMNS]],
) -> Result<(), String> {
    let mut prepared_by_len: HashMap<usize, duckdb::Statement<'_>> = HashMap::new();
    for chunk in rows.chunks(BUCKET_UPSERT_CHUNK_ROWS) {
        if !prepared_by_len.contains_key(&chunk.len()) {
            let sql = connect_schema::upsert_iface_metric_bucket_values_sql(chunk.len());
            let statement = tx.prepare(&sql).map_err(|error| {
                format!("failed to prepare cold iface bucket upsert: {}", error)
            })?;
            prepared_by_len.insert(chunk.len(), statement);
        }
        let statement = prepared_by_len.get_mut(&chunk.len()).expect("prepared above");
        statement.execute(params_from_iter(chunk.iter().flatten().copied())).map_err(|error| {
            format!("failed to write cold iface bucket batch of {} rows: {}", chunk.len(), error)
        })?;
    }
    Ok(())
}

impl ColdStore for DuckdbColdStore {
    fn persist_buckets(
        &self,
        bucket_writes: &[BucketWrite],
        iface_bucket_writes: &[IfaceBucketWrite],
    ) -> Result<BucketPersistStats, String> {
        if bucket_writes.is_empty() && iface_bucket_writes.is_empty() {
            return Ok(BucketPersistStats::default());
        }

        let conn = self.pool.get().map_err(|error| {
            format!("failed to get cold duckdb connection for bucket write: {}", error)
        })?;
        let start = Instant::now();

        let tx = conn.unchecked_transaction().map_err(|error| {
            format!("failed to begin cold duckdb bucket transaction: {}", error)
        })?;

        for kind in [BucketKind::Minute, BucketKind::Hour, BucketKind::Day] {
            let table_rows: Vec<&BucketWrite> =
                bucket_writes.iter().filter(|bucket| bucket.kind == kind).collect();
            if table_rows.is_empty() {
                continue;
            }
            let merged_rows = aggregate_conn_bucket_rows(&table_rows);
            execute_conn_bucket_chunks(&tx, kind.table_name(), &merged_rows)?;
        }

        if !iface_bucket_writes.is_empty() {
            let merged_rows = aggregate_iface_bucket_rows(iface_bucket_writes);
            execute_iface_bucket_chunks(&tx, &merged_rows)?;
        }

        tx.commit().map_err(|error| {
            format!("failed to commit cold duckdb bucket transaction: {}", error)
        })?;

        Ok(BucketPersistStats {
            rows: bucket_writes.len(),
            iface_rows: iface_bucket_writes.len(),
            elapsed_ms: start.elapsed().as_millis(),
        })
    }

    fn persist_dns(&self, metrics: &[DnsMetric]) -> Result<DnsPersistStats, String> {
        if metrics.is_empty() {
            return Ok(DnsPersistStats::default());
        }

        let conn = self.pool.get().map_err(|error| {
            format!("failed to get cold duckdb connection for dns write: {}", error)
        })?;
        let start = Instant::now();

        let sql = dns_batch_insert_sql(metrics.len());
        let mut values: Vec<Box<dyn duckdb::ToSql>> =
            Vec::with_capacity(metrics.len() * DNS_METRIC_COLUMNS);
        for metric in metrics {
            let answers_json = serde_json::to_string(&metric.answers).unwrap_or_default();
            let status_json = serde_json::to_string(&metric.status).unwrap_or_default();
            values.push(Box::new(metric.flow_id as i64));
            values.push(Box::new(metric.domain.clone()));
            values.push(Box::new(metric.query_type.clone()));
            values.push(Box::new(metric.response_code.clone()));
            values.push(Box::new(metric.report_time as i64));
            values.push(Box::new(metric.duration_ms as i64));
            values.push(Box::new(clean_ip_string(&metric.src_ip)));
            values.push(Box::new(answers_json));
            values.push(Box::new(status_json));
        }

        conn.execute(&sql, params_from_iter(values.iter().map(|value| value.as_ref()))).map_err(
            |error| format!("failed to write cold dns batch of {} rows: {}", metrics.len(), error),
        )?;

        Ok(DnsPersistStats {
            rows: metrics.len(),
            elapsed_ms: start.elapsed().as_millis(),
        })
    }

    fn cleanup(&self, config: &MetricRuntimeConfig) -> Result<ColdCleanupStats, String> {
        let conn = self.pool.get().map_err(|error| {
            format!("failed to get cold duckdb connection for cleanup: {}", error)
        })?;
        let now_ms = get_current_time_ms().unwrap_or_default();
        let cutoff_1m = now_ms.saturating_sub(config.connect_1m_retention_days * MS_PER_DAY);
        let cutoff_1h = now_ms.saturating_sub(config.connect_1h_retention_days * MS_PER_DAY);
        let cutoff_1d = now_ms.saturating_sub(config.connect_1d_retention_days * MS_PER_DAY);
        let cutoff_dns = now_ms.saturating_sub(config.dns_retention_days * MS_PER_DAY);

        let deleted_dns = dns_schema::cleanup_old_dns_metrics(&conn, cutoff_dns);
        let stats = cleanup::cleanup_old_cold_metrics_only(
            &conn,
            cutoff_1m,
            cutoff_1h,
            cutoff_1d,
            config.cleanup_time_budget_ms,
            config.cleanup_slice_window_secs,
        );
        tracing::info!(
            "phase=cold_duckdb.cleanup elapsed_ms={} budget_hit={} deleted_iface_5s={} deleted_1m={} deleted_1h={} deleted_1d={} deleted_dns={} deleted_dns_before={}",
            stats.elapsed_ms,
            stats.budget_hit,
            stats.deleted_iface_5s,
            stats.deleted_1m,
            stats.deleted_1h,
            stats.deleted_1d,
            deleted_dns,
            cutoff_dns,
        );

        Ok(ColdCleanupStats {
            deleted_rows: stats.deleted_iface_5s
                + stats.deleted_1m
                + stats.deleted_1h
                + stats.deleted_1d
                + deleted_dns,
            elapsed_ms: stats.elapsed_ms,
        })
    }
}

fn dns_batch_insert_sql(row_count: usize) -> String {
    let values = (0..row_count)
        .map(|index| {
            let base = index * DNS_METRIC_COLUMNS;
            format!(
                "(?{}, ?{}, ?{}, ?{}, ?{}, ?{}, ?{}, ?{}, ?{})",
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO dns_metrics (
            flow_id, domain, query_type, response_code,
            report_time, duration_ms, src_ip, answers, status
        ) VALUES {values}"
    )
}
