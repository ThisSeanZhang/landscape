use duckdb::{params, DuckdbConnectionManager};
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey, ConnectMetric,
    ConnectMetricPoint, MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use r2d2::{self, PooledConnection};
use std::net::IpAddr;
use std::path::PathBuf;
use std::thread;
use tokio::sync::{mpsc, oneshot};

fn clean_ip_string(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.to_string()
            } else {
                v6.to_string()
            }
        }
        IpAddr::V4(v4) => v4.to_string(),
    }
}

pub mod connect;
pub mod dns;

use landscape_common::config::MetricRuntimeConfig;

const A_MIN: u64 = 60 * 1000;
const MS_PER_MINUTE: u64 = A_MIN;
const MS_PER_DAY: u64 = 24 * 3600 * 1000;
const STALE_TIMEOUT_MS: u64 = A_MIN;

/// Database operation messages
pub enum DBMessage {
    // Write Operations
    InsertMetric(ConnectMetric),
    InsertDnsMetric(DnsMetric),

    // Command Operations (Maintenance/Cleanup)
    CollectAndCleanupOldMetrics {
        cutoff_raw: u64,
        cutoff_1m: u64,
        cutoff_1h: u64,
        cutoff_1d: u64,
        cutoff_dns: u64,
        resp: oneshot::Sender<Box<Vec<ConnectMetric>>>,
    },
}

#[derive(Clone)]
pub struct DuckMetricStore {
    tx: mpsc::Sender<DBMessage>,
    pub db_path: PathBuf,
    pub live_db_path: PathBuf,
    pub config: MetricRuntimeConfig,
    pub pool: r2d2::Pool<DuckdbConnectionManager>,
    pub live_pool: r2d2::Pool<DuckdbConnectionManager>,
}

pub fn start_db_thread(
    mut rx: mpsc::Receiver<DBMessage>,
    metric_config: MetricRuntimeConfig,
    db_path: PathBuf,
    conn_conn: PooledConnection<DuckdbConnectionManager>,
    conn_dns: PooledConnection<DuckdbConnectionManager>,
    conn_live: PooledConnection<DuckdbConnectionManager>,
) {
    // 状态管理
    let mut metrics_appender = conn_live.appender("conn_metrics").unwrap();
    let mut dns_appender = conn_dns.appender("dns_metrics").unwrap();
    let mut summary_stmt = conn_live.prepare(connect::SUMMARY_INSERT_SQL).unwrap();
    let mut live_stmt = conn_live.prepare(connect::LIVE_METRIC_INSERT_SQL).unwrap();

    let mut batch_count = 0;
    let flush_interval_duration =
        std::time::Duration::from_secs(landscape_common::DEFAULT_METRIC_FLUSH_INTERVAL_SECS);
    let cleanup_interval_duration =
        std::time::Duration::from_secs(landscape_common::DEFAULT_METRIC_CLEANUP_INTERVAL_SECS);

    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    rt.block_on(async {
        let mut flush_interval = tokio::time::interval(flush_interval_duration);
        let mut cleanup_interval = tokio::time::interval(cleanup_interval_duration);
        loop {
            tokio::select! {
                _ = flush_interval.tick() => {
                    if batch_count > 0 {
                        let _ = metrics_appender.flush();
                        let _ = dns_appender.flush();
                        let _ = connect::perform_batch_rollup(&conn_live, &db_path);
                        batch_count = 0;
                    }
                }
                _ = cleanup_interval.tick() => {
                    let now_ms = landscape_common::utils::time::get_current_time_ms().unwrap_or_default();

                    let cutoff_raw = now_ms.saturating_sub(metric_config.conn_retention_mins * MS_PER_MINUTE);
                    let cutoff_1m = now_ms.saturating_sub(metric_config.conn_retention_minute_days * MS_PER_DAY);
                    let cutoff_1h = now_ms.saturating_sub(metric_config.conn_retention_hour_days * MS_PER_DAY);
                    let cutoff_1d = now_ms.saturating_sub(metric_config.conn_retention_day_days * MS_PER_DAY);
                    let cutoff_dns = now_ms.saturating_sub(metric_config.dns_retention_days * MS_PER_DAY);

                    let _ = metrics_appender.flush();
                    let _ = dns_appender.flush();
                    batch_count = 0;

                    let _ = connect::collect_and_cleanup_old_metrics(
                        &conn_live, cutoff_raw, cutoff_1m, cutoff_1h, cutoff_1d, &db_path,
                    );
                    dns::cleanup_old_dns_metrics(&conn_dns, cutoff_dns);
                    let _ = connect::aggregate_global_stats(&conn_conn);

                    // Cleanup stale live sessions
                    let cutoff_live = now_ms.saturating_sub(STALE_TIMEOUT_MS);
                    let _ = conn_live.execute(
                        "DELETE FROM conn_realtime WHERE last_report_time < ?1",
                        params![cutoff_live as i64],
                    );

                    tracing::info!(
                        "Auto cleanup metrics, raw: {}, 1m: {}, 1h: {}, 1d: {}, dns: {}",
                        cutoff_raw,
                        cutoff_1m,
                        cutoff_1h,
                        cutoff_1d,
                        cutoff_dns
                    );
                }
                msg_opt = rx.recv() => {
                    match msg_opt {
                        Some(msg) => {
                            let mut current_msg = Some(msg);
                            // Process in batches to reduce select! overhead
                            for _ in 0..metric_config.batch_size.max(100) {
                                if let Some(m) = current_msg.take() {
                                    match m {
                                        DBMessage::InsertMetric(metric) => {
                                            let key = &metric.key;
                                            let _ = metrics_appender.append_row(params![
                                                key.create_time as i64,
                                                key.cpu_id as i64,
                                                metric.report_time as i64,
                                                metric.ingress_bytes as i64,
                                                metric.ingress_packets as i64,
                                                metric.egress_bytes as i64,
                                                metric.egress_packets as i64,
                                                {
                                                    let v: u8 = metric.status.clone().into();
                                                    v as i64
                                                },
                                            ]);

                                            // Update live table (rates are calculated by SQL inside)
                                            let _ = connect::update_live_metric(&mut live_stmt, &metric);

                                            // Update memory summary 
                                            let _ = connect::update_summary_by_metric(&mut summary_stmt, &metric);
                                            batch_count += 1;
                                        }
                                        DBMessage::InsertDnsMetric(metric) => {
                                            let _ = dns_appender.append_row(params![
                                                metric.flow_id as i64,
                                                metric.domain,
                                                metric.query_type,
                                                metric.response_code,
                                                metric.report_time as i64,
                                                metric.duration_ms as i64,
                                                clean_ip_string(&metric.src_ip),
                                                serde_json::to_string(&metric.answers).unwrap_or_default(),
                                                serde_json::to_string(&metric.status).unwrap_or_default(),
                                            ]);
                                            batch_count += 1;
                                        }
                                        DBMessage::CollectAndCleanupOldMetrics {
                                            cutoff_raw,
                                            cutoff_1m,
                                            cutoff_1h,
                                            cutoff_1d,
                                            cutoff_dns,
                                            resp,
                                        } => {
                                            let _ = metrics_appender.flush();
                                            let _ = dns_appender.flush();
                                            let _ = connect::perform_batch_rollup(&conn_live, &db_path);
                                            batch_count = 0;
                                            let result = connect::collect_and_cleanup_old_metrics(
                                                &conn_live, cutoff_raw, cutoff_1m, cutoff_1h, cutoff_1d, &db_path,
                                            );

                                            dns::cleanup_old_dns_metrics(&conn_dns, cutoff_dns);
                                            let _ = resp.send(result);
                                        }
                                    }

                                    if batch_count >= metric_config.batch_size {
                                        let _ = metrics_appender.flush();
                                        let _ = dns_appender.flush();
                                        let _ = connect::perform_batch_rollup(&conn_live, &db_path);
                                        batch_count = 0;
                                    }
                                }

                                // Try to get next message without blocking
                                match rx.try_recv() {
                                    Ok(m) => current_msg = Some(m),
                                    Err(_) => break,
                                }
                            }
                        }
                        None => break,
                    }
                }
            }
        }
    });
}

impl DuckMetricStore {
    pub async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let db_path = base_path
            .join(format!("metrics_v{}.duckdb", landscape_common::LANDSCAPE_METRIC_DB_VERSION));
        let live_db_path = PathBuf::from(format!(
            "/dev/shm/landscape_live_v{}.duckdb",
            landscape_common::LANDSCAPE_METRIC_DB_VERSION
        ));

        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).expect("Failed to create base directory");
            }
        }
        let (tx, rx) = mpsc::channel::<DBMessage>(1024);
        let config_clone = config.clone();

        let manager = DuckdbConnectionManager::file_with_flags(
            &db_path,
            duckdb::Config::default()
                .threads(config.max_threads as i64)
                .unwrap()
                .max_memory(&format!("{}MB", config.max_memory))
                .unwrap(),
        )
        .unwrap();
        let pool = r2d2::Pool::builder()
            .max_size((config.max_threads as u32).max(4))
            .build(manager)
            .expect("Failed to create history connection pool");

        let live_manager = DuckdbConnectionManager::file_with_flags(
            &live_db_path,
            duckdb::Config::default()
                .threads(config.max_threads as i64)
                .unwrap()
                .max_memory(&format!("{}MB", config.max_memory))
                .unwrap(),
        )
        .unwrap();
        let live_pool = r2d2::Pool::builder()
            .max_size((config.max_threads as u32).max(4))
            .build(live_manager)
            .expect("Failed to create live connection pool");

        let conn_conn = pool.get().expect("Failed to get CONN writer connection from pool");
        let conn_dns = pool.get().expect("Failed to get DNS writer connection from pool");
        let conn_live = live_pool.get().expect("Failed to get LIVE writer connection from pool");

        // Ensure tables are created before returning to avoid race conditions
        connect::create_summaries_table(&conn_conn);
        connect::create_metrics_table(&conn_conn).expect("Failed to create connect metrics tables");
        dns::create_dns_table(&conn_dns).expect("Failed to create DNS metrics tables");

        // Attach memory database for live metrics (only once)
        connect::create_live_tables(&conn_live).expect("Failed to create live tables");

        // Performance optimizations: decrease checkpoint frequency
        let _ = conn_conn.execute("PRAGMA wal_autocheckpoint='256MB'", []);
        let _ = conn_dns.execute("PRAGMA wal_autocheckpoint='256MB'", []);
        let _ = conn_live.execute("PRAGMA wal_autocheckpoint='256MB'", []);

        // Initial aggregation
        let _ = connect::aggregate_global_stats(&conn_conn);

        let thread_db_path = db_path.clone();
        thread::spawn(move || {
            start_db_thread(rx, config_clone, thread_db_path, conn_conn, conn_dns, conn_live);
        });

        DuckMetricStore { tx, db_path, live_db_path, config, pool, live_pool }
    }

    /// Internal helper to get a history read connection
    fn get_read_conn(&self) -> r2d2::PooledConnection<DuckdbConnectionManager> {
        self.pool.get().expect("Failed to get history read connection from pool")
    }

    /// Internal helper to get a live read connection
    fn get_live_conn(&self) -> r2d2::PooledConnection<DuckdbConnectionManager> {
        self.live_pool.get().expect("Failed to get live read connection from pool")
    }

    pub async fn insert_metric(&self, metric: ConnectMetric) {
        let _ = self.tx.send(DBMessage::InsertMetric(metric)).await;
    }

    pub async fn connect_infos(
        &self,
    ) -> Vec<landscape_common::metric::connect::ConnectRealtimeStatus> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_live_conn();
            let mut stmt = conn
                .prepare(
                    "
                SELECT 
                    create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, 
                    l4_proto, l3_proto, flow_id, trace_id,
                    ingress_bytes, egress_bytes, ingress_packets, egress_packets,
                    ingress_bps, egress_bps, ingress_pps, egress_pps,
                    status, last_report_time
                FROM conn_realtime
                ORDER BY create_time
            ",
                )
                .unwrap();

            let rows = stmt
                .query_map([], |row| {
                    Ok(landscape_common::metric::connect::ConnectRealtimeStatus {
                        key: ConnectKey {
                            create_time: row.get::<_, i64>(0)? as u64,
                            cpu_id: row.get::<_, i64>(1)? as u32,
                        },
                        src_ip: row
                            .get::<_, String>(2)?
                            .parse()
                            .unwrap_or("0.0.0.0".parse().unwrap()),
                        dst_ip: row
                            .get::<_, String>(3)?
                            .parse()
                            .unwrap_or("0.0.0.0".parse().unwrap()),
                        src_port: row.get::<_, i64>(4)? as u16,
                        dst_port: row.get::<_, i64>(5)? as u16,
                        l4_proto: row.get::<_, i64>(6)? as u8,
                        l3_proto: row.get::<_, i64>(7)? as u8,
                        flow_id: row.get::<_, i64>(8)? as u8,
                        trace_id: row.get::<_, i64>(9)? as u8,
                        ingress_bps: row.get::<_, i64>(14)? as u64,
                        egress_bps: row.get::<_, i64>(15)? as u64,
                        ingress_pps: row.get::<_, i64>(16)? as u64,
                        egress_pps: row.get::<_, i64>(17)? as u64,
                        last_report_time: row.get::<_, i64>(19)? as u64,
                        status: row.get::<_, u8>(18)?.into(),
                    })
                })
                .unwrap();

            rows.filter_map(Result::ok).collect()
        })
        .await
        .unwrap_or_default()
    }

    pub async fn get_realtime_ip_stats(
        &self,
        is_src: bool,
    ) -> Vec<landscape_common::metric::connect::IpRealtimeStat> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_live_conn();
            let group_col = if is_src { "src_ip" } else { "dst_ip" };
            let sql = format!(
                "
                SELECT 
                    {}, 
                    SUM(ingress_bps), SUM(egress_bps), 
                    SUM(ingress_pps), SUM(egress_pps), 
                    COUNT(*)
                FROM conn_realtime
                GROUP BY {}
            ",
                group_col, group_col
            );

            let mut stmt = conn.prepare(&sql).unwrap();
            let rows = stmt
                .query_map([], |row| {
                    Ok(landscape_common::metric::connect::IpRealtimeStat {
                        ip: row.get::<_, String>(0)?.parse().unwrap_or("0.0.0.0".parse().unwrap()),
                        stats: landscape_common::metric::connect::IpAggregatedStats {
                            ingress_bps: row.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64,
                            egress_bps: row.get::<_, Option<i64>>(2)?.unwrap_or(0) as u64,
                            ingress_pps: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64,
                            egress_pps: row.get::<_, Option<i64>>(4)?.unwrap_or(0) as u64,
                            active_conns: row.get::<_, i64>(5)? as u32,
                        },
                    })
                })
                .unwrap();

            rows.filter_map(Result::ok).collect()
        })
        .await
        .unwrap_or_default()
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || -> Vec<ConnectMetricPoint> {
            let conn = store.get_live_conn();
            connect::query_metric_by_key(&conn, &key, resolution, Some(&store.db_path))
        })
        .await
        .unwrap_or_default()
    }

    pub async fn current_active_connect_keys(&self) -> Vec<ConnectKey> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || -> Vec<ConnectKey> {
            let conn = store.get_read_conn();
            connect::current_active_connect_keys(&conn)
        })
        .await
        .unwrap_or_default()
    }

    pub async fn collect_and_cleanup_old_metrics(
        &self,
        cutoff_raw: u64,
        cutoff_1m: u64,
        cutoff_1h: u64,
        cutoff_1d: u64,
    ) -> Box<Vec<ConnectMetric>> {
        let (resp, rx) = oneshot::channel();
        let now_ms = landscape_common::utils::time::get_current_time_ms().unwrap_or_default();
        let cutoff_dns = now_ms.saturating_sub(self.config.dns_retention_days * MS_PER_DAY);

        let _ = self
            .tx
            .send(DBMessage::CollectAndCleanupOldMetrics {
                cutoff_raw,
                cutoff_1m,
                cutoff_1h,
                cutoff_1d,
                cutoff_dns,
                resp,
            })
            .await;
        rx.await.unwrap()
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            connect::query_historical_summaries_complex(&conn, params)
        })
        .await
        .unwrap_or_default()
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<landscape_common::metric::connect::IpHistoryStat> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            connect::query_connection_ip_history(&conn, params, true)
        })
        .await
        .unwrap_or_default()
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<landscape_common::metric::connect::IpHistoryStat> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            connect::query_connection_ip_history(&conn, params, false)
        })
        .await
        .unwrap_or_default()
    }

    pub async fn get_global_stats(&self) -> ConnectGlobalStats {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            connect::query_global_stats(&conn)
        })
        .await
        .unwrap_or_default()
    }

    pub async fn insert_dns_metric(&self, mut metric: DnsMetric) {
        if metric.domain.ends_with('.') && metric.domain.len() > 1 {
            metric.domain.pop();
        }
        let _ = self.tx.send(DBMessage::InsertDnsMetric(metric)).await;
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            dns::query_dns_history(&conn, params)
        })
        .await
        .unwrap_or(DnsHistoryResponse { items: Vec::new(), total: 0 })
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            dns::query_dns_summary(&conn, params)
        })
        .await
        .unwrap_or_else(|_| DnsSummaryResponse::default())
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            dns::query_dns_lightweight_summary(&conn, params)
        })
        .await
        .unwrap_or_else(|_| DnsLightweightSummaryResponse::default())
    }
}
