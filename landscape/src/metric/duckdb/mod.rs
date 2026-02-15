use duckdb::{params, DuckdbConnectionManager};
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey, ConnectMetric,
    MetricResolution,
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

const MS_PER_HOUR: u64 = 3600 * 1000;
const MS_PER_DAY: u64 = 24 * 3600 * 1000;

/// Database operation messages
pub enum DBMessage {
    // Write Operations
    InsertMetric(ConnectMetric),
    InsertDnsMetric(DnsMetric),

    // Command Operations (Maintenance/Cleanup)
    CollectAndCleanupOldMetrics {
        cutoff_raw: u64,
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
    pub config: MetricRuntimeConfig,
    pub pool: r2d2::Pool<DuckdbConnectionManager>,
}

pub fn start_db_thread(
    mut rx: mpsc::Receiver<DBMessage>,
    metric_config: MetricRuntimeConfig,
    conn_conn: PooledConnection<DuckdbConnectionManager>,
    conn_dns: PooledConnection<DuckdbConnectionManager>,
) {
    // 初始化表
    connect::create_summaries_table(&conn_conn);
    connect::create_metrics_table(&conn_conn).unwrap();
    dns::create_dns_table(&conn_dns).unwrap();

    // 状态管理
    let mut metrics_appender = conn_conn.appender("conn_metrics").unwrap();
    let mut dns_appender = conn_dns.appender("dns_metrics").unwrap();
    let mut summary_stmt = conn_conn.prepare(connect::SUMMARY_INSERT_SQL).unwrap();
    let mut metrics_1h_stmt = conn_conn.prepare(connect::METRICS_1H_INSERT_SQL).unwrap();
    let mut metrics_1d_stmt = conn_conn.prepare(connect::METRICS_1D_INSERT_SQL).unwrap();

    let mut batch_count = 0;
    let flush_interval =
        std::time::Duration::from_secs(landscape_common::DEFAULT_METRIC_FLUSH_INTERVAL_SECS);
    let mut last_flush = std::time::Instant::now();
    let mut last_cleanup = std::time::Instant::now();
    let cleanup_interval =
        std::time::Duration::from_secs(landscape_common::DEFAULT_METRIC_CLEANUP_INTERVAL_SECS);

    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    rt.block_on(async {
        loop {
            let now = std::time::Instant::now();
            let remaining = flush_interval.saturating_sub(now.duration_since(last_flush));

            let timeout_res = tokio::time::timeout(remaining, rx.recv()).await;

            match timeout_res {
                Ok(Some(msg)) => {
                    match msg {
                        // --- 写入类操作 ---
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

                            // Insert into Hourly Table (Truncate to hour)
                            let hour_ts = (metric.report_time / MS_PER_HOUR) * MS_PER_HOUR;
                            let _ = metrics_1h_stmt.execute(params![
                                key.create_time as i64,
                                key.cpu_id as i64,
                                hour_ts as i64,
                                metric.ingress_bytes as i64,
                                metric.ingress_packets as i64,
                                metric.egress_bytes as i64,
                                metric.egress_packets as i64,
                                {
                                    let v: u8 = metric.status.clone().into();
                                    v as i64
                                },
                            ]);

                            // Insert into Daily Table (Truncate to day)
                            let day_ts = (metric.report_time / MS_PER_DAY) * MS_PER_DAY;
                            let _ = metrics_1d_stmt.execute(params![
                                key.create_time as i64,
                                key.cpu_id as i64,
                                day_ts as i64,
                                metric.ingress_bytes as i64,
                                metric.ingress_packets as i64,
                                metric.egress_bytes as i64,
                                metric.egress_packets as i64,
                                {
                                    let v: u8 = metric.status.clone().into();
                                    v as i64
                                },
                            ]);

                            if connect::update_summary_by_metric(&mut summary_stmt, &metric).is_ok()
                            {
                                batch_count += 1;
                            }
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

                        // --- 管理类操作 ---
                        DBMessage::CollectAndCleanupOldMetrics {
                            cutoff_raw,
                            cutoff_1h,
                            cutoff_1d,
                            cutoff_dns,
                            resp,
                        } => {
                            let _ = metrics_appender.flush();
                            let _ = dns_appender.flush();
                            batch_count = 0;
                            last_flush = std::time::Instant::now();
                            let result = connect::collect_and_cleanup_old_metrics(
                                &conn_conn, cutoff_raw, cutoff_1h, cutoff_1d,
                            );

                            dns::cleanup_old_dns_metrics(&conn_dns, cutoff_dns);
                            let _ = resp.send(result);
                        }
                    }

                    if batch_count >= landscape_common::DEFAULT_METRIC_BATCH_SIZE {
                        let _ = metrics_appender.flush();
                        let _ = dns_appender.flush();
                        batch_count = 0;
                        last_flush = std::time::Instant::now();
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    if batch_count > 0 {
                        let _ = metrics_appender.flush();
                        let _ = dns_appender.flush();
                        batch_count = 0;
                    }
                    last_flush = std::time::Instant::now();
                }
            }

            if last_cleanup.elapsed() > cleanup_interval {
                let now_ms =
                    landscape_common::utils::time::get_current_time_ms().unwrap_or_default();

                let cutoff_raw =
                    now_ms.saturating_sub(metric_config.conn_retention_days * MS_PER_DAY);
                let cutoff_1h =
                    now_ms.saturating_sub(metric_config.conn_retention_hour_days * MS_PER_DAY);
                let cutoff_1d =
                    now_ms.saturating_sub(metric_config.conn_retention_day_days * MS_PER_DAY);
                let cutoff_dns =
                    now_ms.saturating_sub(metric_config.dns_retention_days * MS_PER_DAY);

                let _ = metrics_appender.flush();
                let _ = dns_appender.flush();
                batch_count = 0;
                last_flush = std::time::Instant::now();
                last_cleanup = std::time::Instant::now();

                let _ = connect::collect_and_cleanup_old_metrics(
                    &conn_conn, cutoff_raw, cutoff_1h, cutoff_1d,
                );
                dns::cleanup_old_dns_metrics(&conn_dns, cutoff_dns);
                tracing::info!(
                    "Auto cleanup metrics, raw: {}, 1h: {}, 1d: {}, dns: {}",
                    cutoff_raw,
                    cutoff_1h,
                    cutoff_1d,
                    cutoff_dns
                );
            }
        }
    });
}

impl DuckMetricStore {
    pub async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let db_path = base_path
            .join(format!("metrics_v{}.duckdb", landscape_common::LANDSCAPE_METRIC_DB_VERSION));

        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).expect("Failed to create base directory");
            }
        }
        let (tx, rx) = mpsc::channel::<DBMessage>(1024);
        let config_clone = config.clone();

        let db_config = duckdb::Config::default()
            .threads(config.max_threads as i64)
            .unwrap()
            .max_memory(&format!("{}MB", config.max_memory))
            .unwrap();

        let manager = DuckdbConnectionManager::file_with_flags(&db_path, db_config).unwrap();
        let pool = r2d2::Pool::builder()
            .max_size((config.max_threads as u32).max(4)) // Ensure at least 4 connections
            .build(manager)
            .expect("Failed to create connection pool");

        let conn_conn = pool.get().expect("Failed to get CONN writer connection from pool");
        let conn_dns = pool.get().expect("Failed to get DNS writer connection from pool");

        thread::spawn(move || {
            start_db_thread(rx, config_clone, conn_conn, conn_dns);
        });

        DuckMetricStore { tx, db_path, config, pool }
    }

    /// Internal helper to get a read connection
    fn get_read_conn(&self) -> r2d2::PooledConnection<DuckdbConnectionManager> {
        self.pool.get().expect("Failed to get read connection from pool")
    }

    pub async fn insert_metric(&self, metric: ConnectMetric) {
        let _ = self.tx.send(DBMessage::InsertMetric(metric)).await;
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetric> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            connect::query_metric_by_key(&conn, &key, resolution)
        })
        .await
        .unwrap_or_default()
    }

    pub async fn current_active_connect_keys(&self) -> Vec<ConnectKey> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || {
            let conn = store.get_read_conn();
            connect::current_active_connect_keys(&conn)
        })
        .await
        .unwrap_or_default()
    }

    pub async fn collect_and_cleanup_old_metrics(
        &self,
        cutoff_raw: u64,
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
