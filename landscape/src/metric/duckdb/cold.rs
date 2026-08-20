use duckdb::{params, params_from_iter, DuckdbConnectionManager};
use landscape_common::config::MetricRuntimeConfig;
use landscape_common::metric::dns::DnsMetric;
use landscape_core::time::get_current_time_ms;
use std::time::Instant;

use crate::metric::cold::{BucketPersistStats, ColdCleanupStats, ColdStore, DnsPersistStats};
use crate::metric::ingest::{clean_ip_string, BucketWrite, IfaceBucketWrite, MS_PER_DAY};

use super::connect::{cleanup, schema as connect_schema};
use super::dns::schema as dns_schema;

const DNS_METRIC_COLUMNS: usize = 9;

/// DuckDB-backed cold history store.
///
/// All writes are batch-oriented: bucket upserts run inside a single
/// transaction with reused prepared statements, and DNS metrics are inserted
/// as one multi-row statement per batch.
pub(crate) struct DuckdbColdStore {
    pool: r2d2::Pool<DuckdbConnectionManager>,
}

impl DuckdbColdStore {
    pub(crate) fn new(pool: r2d2::Pool<DuckdbConnectionManager>) -> Self {
        Self { pool }
    }
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

        if !bucket_writes.is_empty() {
            let mut prepared_table: Option<&str> = None;
            let mut prepared_stmt: Option<duckdb::Statement<'_>> = None;
            for bucket in bucket_writes {
                let table = bucket.kind.table_name();
                if prepared_table != Some(table) {
                    prepared_stmt = Some(
                        tx.prepare(&connect_schema::upsert_metric_bucket_values_sql(table))
                            .map_err(|error| {
                                format!(
                                    "failed to prepare cold bucket upsert for {}: {}",
                                    table, error
                                )
                            })?,
                    );
                    prepared_table = Some(table);
                }
                let status: u8 = bucket.metric.status.clone().into();
                prepared_stmt
                    .as_mut()
                    .expect("prepared bucket upsert")
                    .execute(params![
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
                    ])
                    .map_err(|error| {
                        format!("failed to write cold bucket row into {}: {}", table, error)
                    })?;
            }
            drop(prepared_stmt);
        }

        if !iface_bucket_writes.is_empty() {
            let mut prepared_stmt =
                tx.prepare(&connect_schema::upsert_iface_metric_bucket_values_sql()).map_err(
                    |error| format!("failed to prepare cold iface bucket upsert: {}", error),
                )?;
            for bucket in iface_bucket_writes {
                prepared_stmt
                    .execute(params![
                        bucket.ifindex as i64,
                        bucket.report_time as i64,
                        bucket.ingress_bytes as i64,
                        bucket.ingress_packets as i64,
                        bucket.egress_bytes as i64,
                        bucket.egress_packets as i64,
                        bucket.active_conns as i64,
                    ])
                    .map_err(|error| format!("failed to write cold iface bucket row: {}", error))?;
            }
            drop(prepared_stmt);
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
