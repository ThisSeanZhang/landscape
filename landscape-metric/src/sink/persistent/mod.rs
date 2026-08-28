pub(crate) mod sqlite;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use landscape_common::config::MetricRuntimeConfig;
use landscape_common::database::error::DbError;
use landscape_common::metric::connect::{
    ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
    ConnectMetricPoint, IpHistoryStat, MetricResolution,
};
use landscape_common::metric::dns::{
    DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsMetric,
    DnsSummaryQueryParams, DnsSummaryResponse,
};
use landscape_core::time::get_current_time_ms;
use sqlx::SqlitePool;
use tokio::task::JoinHandle;

use super::MetricSink;
use crate::agg::dns_bucket::{DnsBucketRow, DnsSummaryParts};
use crate::agg::{Batch, MS_PER_DAY};

/// 全局统计缓存每日漂移校正间隔:超过该时长未重建则后台重建一次。
const GLOBAL_STATS_REBUILD_INTERVAL_SECS: u64 = 24 * 3600;

/// cleanup 路径单次容量强制的删除行数预算。
const CLEANUP_MAX_DELETE_ROWS: u64 = 100_000;
/// SQLITE_FULL 热路径回收的单次删除行数预算(控制写入路径延迟)。
const HOT_RECLAIM_MAX_DELETE_ROWS: u64 = 10_000;

/// 持久化 sink:聚合批次以单事务批量写入 sqlite,历史查询直接查库。
#[derive(Clone)]
pub(crate) struct PersistentMetricStore {
    connect_pool: SqlitePool,
    dns_pool: SqlitePool,
    connect_db_path: PathBuf,
    dns_db_path: PathBuf,
    connect_db_max_bytes: u64,
    dns_db_max_bytes: u64,
    rebuild_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl PersistentMetricStore {
    /// 仅供测试使用:以默认配置构建存储。生产路径统一走 `new_with_config`。
    #[cfg(test)]
    pub(crate) async fn new(base_path: PathBuf) -> Result<Self, String> {
        let config = MetricRuntimeConfig {
            mode: landscape_common::config::MetricMode::Persistent,
            connect_second_window_minutes: 5,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 7,
            connect_1d_retention_days: 30,
            connect_summary_retention_days: 30,
            connect_summary_max_rows: landscape_common::DEFAULT_METRIC_CONNECT_SUMMARY_MAX_ROWS,
            connect_db_max_bytes: landscape_common::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES,
            dns_retention_days: 7,
            dns_1m_retention_days: 30,
            dns_db_max_bytes: landscape_common::DEFAULT_DNS_METRIC_DB_MAX_BYTES,
            write_batch_size: 20_000,
            write_flush_interval_secs: 30,
            cleanup_interval_secs: 300,
            cleanup_time_budget_ms: 2_000,
            cleanup_slice_window_secs: 300,
        };
        Self::new_with_config(base_path, &config).await
    }

    pub(crate) async fn new_with_config(
        base_path: PathBuf,
        config: &MetricRuntimeConfig,
    ) -> Result<Self, String> {
        if !base_path.exists() {
            std::fs::create_dir_all(&base_path).map_err(|error| {
                format!(
                    "failed to create persistent metric directory {}: {}",
                    base_path.display(),
                    error
                )
            })?;
        }

        let version = landscape_common::LANDSCAPE_METRIC_DB_VERSION;
        // 库文件按版本号命名:结构变更时递增 LANDSCAPE_METRIC_DB_VERSION 即得新库,
        // 旧库文件不再读写(见 landscape-common::LANDSCAPE_METRIC_DB_VERSION 的注释约定)。
        let connect_db_path = base_path.join(format!("metrics_v{version}_connect.sqlite"));
        let dns_db_path = base_path.join(format!("metrics_v{version}_dns.sqlite"));

        let connect_pool =
            sqlite::open_connect_pool(&connect_db_path, config.connect_db_max_bytes).await?;
        let dns_pool = sqlite::open_dns_pool(&dns_db_path, config.dns_db_max_bytes).await?;

        tracing::info!(
            "persistent metric store ready: connect_db={} dns_db={}",
            connect_db_path.display(),
            dns_db_path.display()
        );

        Ok(Self {
            connect_pool,
            dns_pool,
            connect_db_path,
            dns_db_path,
            connect_db_max_bytes: config.connect_db_max_bytes,
            dns_db_max_bytes: config.dns_db_max_bytes,
            rebuild_handle: Arc::new(Mutex::new(None)),
        })
    }

    /// 数据库满(SQLITE_FULL)时的热路径回收:删除少量最旧数据并压缩,
    /// 为一次写入重试腾出 freelist 空间。返回是否删除过数据(值得重试一次)。
    ///
    /// 注意:此处以 `rebuild_cache=false` 直接删除行,**不更新
    /// conn_global_stats_cache**(删除行对应字节/连接数在重试成功前仍计入全局
    /// 统计)。误差窗口 ≤ 下一轮 cleanup(cleanup 路径 `rebuild_cache=true`
    /// 全表重建修正,默认间隔 5 分钟)或每日漂移重建;为避免满库时每次 FULL
    /// 都全表扫描重建缓存,这里刻意不做修正。
    async fn reclaim_connect_space(&self) -> bool {
        if self.connect_db_max_bytes == 0 {
            // 未配置容量上限:SQLITE_FULL 说明磁盘真的满了,删数据也无法缩容。
            return false;
        }
        let deleted = match sqlite::connect::enforce_database_size(
            &self.connect_pool,
            None,
            HOT_RECLAIM_MAX_DELETE_ROWS,
            false,
        )
        .await
        {
            Ok(deleted) => deleted,
            Err(error) => {
                tracing::error!("failed to reclaim persistent connect database space: {}", error);
                return false;
            }
        };
        if deleted == 0 {
            return false;
        }
        if let Err(error) = sqlite::checkpoint_and_compact(&self.connect_pool).await {
            tracing::warn!("failed to compact connect sqlite: {}", error);
        }
        true
    }

    async fn reclaim_dns_space(&self) -> bool {
        if self.dns_db_max_bytes == 0 {
            return false;
        }
        let deleted = match sqlite::dns::enforce_database_size(
            &self.dns_pool,
            None,
            HOT_RECLAIM_MAX_DELETE_ROWS,
        )
        .await
        {
            Ok(deleted) => deleted,
            Err(error) => {
                tracing::error!("failed to reclaim persistent dns database space: {}", error);
                return false;
            }
        };
        if deleted == 0 {
            return false;
        }
        if let Err(error) = sqlite::checkpoint_and_compact(&self.dns_pool).await {
            tracing::warn!("failed to compact dns sqlite: {}", error);
        }
        true
    }
}

#[async_trait::async_trait]
impl MetricSink for PersistentMetricStore {
    async fn apply_connect_batch(&self, batch: &Batch) -> bool {
        if batch.is_empty() {
            return true;
        }
        // 行为决策:写失败直接丢批次、不重试。metric 数据非关键路径,背压/重试会拖垮
        // 采集链路;代价是断电或磁盘异常时会丢少量聚合数据,因此必须保留 error 日志便于排查。
        // 唯一例外:数据库满(SQLITE_FULL)时先做一次小预算回收(删最旧 + 压缩)再重试一次,
        // 避免容量上限到达后写入路径持续丢批、只等每轮 cleanup 腾空间。
        match sqlite::connect::apply_connect_batch(&self.connect_pool, batch).await {
            Ok(()) => true,
            Err(error) => {
                if sqlite::is_sqlite_full(&error) && self.reclaim_connect_space().await {
                    if let Err(retry_error) =
                        sqlite::connect::apply_connect_batch(&self.connect_pool, batch).await
                    {
                        tracing::error!(
                            "failed to write persistent connect batch (retry after reclaim), dropping it: {}",
                            retry_error
                        );
                        return false;
                    }
                    return true;
                }
                tracing::error!("failed to write persistent connect batch, dropping it: {}", error);
                false
            }
        }
    }

    async fn apply_dns_batch(&self, metrics: Vec<DnsMetric>) -> bool {
        if metrics.is_empty() {
            return true;
        }
        match sqlite::dns::insert_dns_batch(&self.dns_pool, &metrics).await {
            Ok(()) => true,
            Err(error) => {
                if sqlite::is_sqlite_full(&error) && self.reclaim_dns_space().await {
                    if let Err(retry_error) =
                        sqlite::dns::insert_dns_batch(&self.dns_pool, &metrics).await
                    {
                        tracing::error!(
                            "failed to write persistent dns batch (retry after reclaim), dropping it: {}",
                            retry_error
                        );
                        return false;
                    }
                    return true;
                }
                tracing::error!("failed to write persistent dns batch, dropping it: {}", error);
                false
            }
        }
    }

    async fn apply_dns_bucket_rows(&self, rows: Vec<DnsBucketRow>) -> bool {
        if rows.is_empty() {
            return true;
        }
        match sqlite::dns::insert_dns_bucket_rows(&self.dns_pool, &rows).await {
            Ok(()) => true,
            Err(error) => {
                if sqlite::is_sqlite_full(&error) && self.reclaim_dns_space().await {
                    if let Err(retry_error) =
                        sqlite::dns::insert_dns_bucket_rows(&self.dns_pool, &rows).await
                    {
                        tracing::error!(
                            "failed to write persistent dns metric buckets (retry after reclaim), dropping them: {}",
                            retry_error
                        );
                        return false;
                    }
                    return true;
                }
                tracing::error!(
                    "failed to write persistent dns metric buckets, dropping them: {}",
                    error
                );
                false
            }
        }
    }

    async fn cleanup_connect(&self, config: &MetricRuntimeConfig) {
        let now_ms = get_current_time_ms().unwrap_or_default();

        let summary_cutoff =
            now_ms.saturating_sub(config.connect_summary_retention_days.saturating_mul(MS_PER_DAY));
        if let Err(error) =
            sqlite::connect::cleanup_old_summaries(&self.connect_pool, summary_cutoff).await
        {
            tracing::error!("failed to cleanup persistent conn_summaries: {}", error);
        }

        if let Err(error) = sqlite::connect::enforce_summary_max_rows(
            &self.connect_pool,
            config.connect_summary_max_rows,
        )
        .await
        {
            tracing::error!("failed to enforce persistent conn_summaries max rows: {}", error);
        }

        let cutoffs = [
            (
                crate::agg::BucketKind::Minute,
                now_ms.saturating_sub(config.connect_1m_retention_days.saturating_mul(MS_PER_DAY)),
            ),
            (
                crate::agg::BucketKind::Hour,
                now_ms.saturating_sub(config.connect_1h_retention_days.saturating_mul(MS_PER_DAY)),
            ),
            (
                crate::agg::BucketKind::Day,
                now_ms.saturating_sub(config.connect_1d_retention_days.saturating_mul(MS_PER_DAY)),
            ),
        ];
        if let Err(error) = sqlite::connect::cleanup_old_buckets(
            &self.connect_pool,
            cutoffs,
            config.cleanup_time_budget_ms,
            config.cleanup_slice_window_secs,
        )
        .await
        {
            tracing::error!("failed to cleanup persistent connect buckets: {}", error);
        }
        // 容量控制:以上限的 90% 为清理目标提前删除最旧数据(而非等塞满再删),
        // 给本 cleanup 间隔内的写入留出余量,避免触达 max_page_count 而 SQLITE_FULL。
        if self.connect_db_max_bytes > 0 {
            let target = self.connect_db_max_bytes - self.connect_db_max_bytes / 10;
            match sqlite::connect::enforce_database_size(
                &self.connect_pool,
                Some(target),
                CLEANUP_MAX_DELETE_ROWS,
                true,
            )
            .await
            {
                Ok(deleted) => {
                    if deleted > 0 {
                        tracing::info!(
                            "phase=persistent_connect.size_enforce deleted_rows={} target_bytes={}",
                            deleted,
                            target
                        );
                        if let Err(error) = sqlite::checkpoint_and_compact(&self.connect_pool).await
                        {
                            tracing::warn!("failed to compact connect sqlite: {}", error);
                        }
                    }
                    // 收敛保护:删除预算耗尽仍未回到目标以下时明确告警,
                    // 下一轮 cleanup 会继续收敛。
                    match sqlite::logical_main_size_bytes(&self.connect_pool).await {
                        Ok(logical) if logical > target => {
                            tracing::warn!(
                                path = %self.connect_db_path.display(),
                                logical_bytes = logical,
                                target_bytes = target,
                                "connect metric database is still over the cleanup target; \
                                 delete budget exhausted, will continue on the next round"
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                "failed to measure connect database size after cleanup: {}",
                                error
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::error!(
                        "failed to enforce persistent connect database size: {}",
                        error
                    );
                }
            }
        }
        if let Err(error) = sqlite::checkpoint_and_compact(&self.connect_pool).await {
            tracing::warn!("failed to compact connect sqlite: {}", error);
        }

        // 回收已结束的后台任务。失败或 panic 后下一轮允许重试。
        let finished_handle = {
            let mut guard =
                crate::lock_or_recover(&self.rebuild_handle, "persistent rebuild handle");
            if guard.as_ref().map(|handle| handle.is_finished()).unwrap_or(false) {
                guard.take()
            } else {
                None
            }
        };
        if let Some(handle) = finished_handle {
            let _ = handle.await;
        }

        // 每日漂移校正:缓存超过 24h 未重建时,后台异步全量重建;
        // 同一时刻至多一个重建任务。
        match sqlite::connect::global_stats_stale(
            &self.connect_pool,
            GLOBAL_STATS_REBUILD_INTERVAL_SECS,
        )
        .await
        {
            Ok(true) => {
                let mut guard =
                    crate::lock_or_recover(&self.rebuild_handle, "persistent rebuild handle");
                if guard.is_none() {
                    tracing::info!(
                        "phase=persistent_connect.global_stats_rebuild starting daily drift correction rebuild"
                    );
                    let rebuild_pool = self.connect_pool.clone();
                    *guard = Some(tokio::spawn(async move {
                        if let Err(error) =
                            sqlite::connect::rebuild_global_stats_cache(&rebuild_pool).await
                        {
                            tracing::error!(
                                "failed to rebuild persistent connect global stats cache: {}",
                                error
                            );
                        }
                    }));
                }
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(
                    "failed to check persistent connect global stats cache staleness: {}",
                    error
                );
            }
        }
    }

    async fn cleanup_dns(&self, config: &MetricRuntimeConfig) {
        let cutoff = get_current_time_ms()
            .unwrap_or_default()
            .saturating_sub(config.dns_retention_days.saturating_mul(MS_PER_DAY));
        match sqlite::dns::cleanup_old_dns(
            &self.dns_pool,
            cutoff,
            config.cleanup_time_budget_ms,
            config.cleanup_slice_window_secs,
        )
        .await
        {
            Ok(deleted) => {
                tracing::debug!("phase=persistent_dns.cleanup deleted_rows={}", deleted)
            }
            Err(error) => {
                tracing::error!("failed to cleanup persistent dns metrics: {}", error)
            }
        }

        let bucket_cutoff = get_current_time_ms()
            .unwrap_or_default()
            .saturating_sub(config.dns_1m_retention_days.saturating_mul(MS_PER_DAY));
        if let Err(error) = sqlite::dns::cleanup_old_dns_buckets(
            &self.dns_pool,
            bucket_cutoff,
            config.cleanup_time_budget_ms,
            config.cleanup_slice_window_secs,
        )
        .await
        {
            tracing::error!("failed to cleanup persistent dns metric buckets: {}", error);
        }
        // 容量控制:同 connect,以上限的 90% 为清理目标提前删除最旧数据。
        if self.dns_db_max_bytes > 0 {
            let target = self.dns_db_max_bytes - self.dns_db_max_bytes / 10;
            match sqlite::dns::enforce_database_size(
                &self.dns_pool,
                Some(target),
                CLEANUP_MAX_DELETE_ROWS,
            )
            .await
            {
                Ok(deleted) => {
                    if deleted > 0 {
                        tracing::info!(
                            "phase=persistent_dns.size_enforce deleted_rows={} target_bytes={}",
                            deleted,
                            target
                        );
                        if let Err(error) = sqlite::checkpoint_and_compact(&self.dns_pool).await {
                            tracing::warn!("failed to compact dns sqlite: {}", error);
                        }
                    }
                    match sqlite::logical_main_size_bytes(&self.dns_pool).await {
                        Ok(logical) if logical > target => {
                            tracing::warn!(
                                path = %self.dns_db_path.display(),
                                logical_bytes = logical,
                                target_bytes = target,
                                "dns metric database is still over the cleanup target; \
                                 delete budget exhausted, will continue on the next round"
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(
                                "failed to measure dns database size after cleanup: {}",
                                error
                            );
                        }
                    }
                }
                Err(error) => {
                    tracing::error!("failed to enforce persistent dns database size: {}", error);
                }
            }
        }
        if let Err(error) = sqlite::checkpoint_and_compact(&self.dns_pool).await {
            tracing::warn!("failed to compact dns sqlite: {}", error);
        }
    }

    async fn close(&self) {
        let handle =
            crate::lock_or_recover(&self.rebuild_handle, "persistent rebuild handle").take();
        if let Some(handle) = handle {
            let _ = handle.await;
        }
        self.connect_pool.close().await;
        self.dns_pool.close().await;
    }

    async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        match sqlite::connect::query_metric_by_key(&self.connect_pool, &key, resolution).await {
            Ok(points) => points,
            Err(error) => {
                tracing::error!("failed to query persistent connect metrics by key: {}", error);
                Vec::new()
            }
        }
    }

    async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> ConnectHistoryResponse {
        match sqlite::connect::query_historical_summaries_complex(&self.connect_pool, params).await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect history summaries: {}", error);
                ConnectHistoryResponse::default()
            }
        }
    }

    async fn history_src_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match sqlite::connect::query_connection_ip_history(&self.connect_pool, params, true).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect src ip history: {}", error);
                Vec::new()
            }
        }
    }

    async fn history_dst_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match sqlite::connect::query_connection_ip_history(&self.connect_pool, params, false).await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!("failed to query persistent connect dst ip history: {}", error);
                Vec::new()
            }
        }
    }

    async fn get_global_stats(&self, force_refresh: bool) -> Result<ConnectGlobalStats, DbError> {
        if force_refresh {
            sqlite::connect::rebuild_global_stats_cache(&self.connect_pool).await.map_err(|error| {
                DbError::Internal(format!(
                    "failed to rebuild persistent connect global stats cache: {}",
                    error
                ))
            })
        } else {
            sqlite::connect::query_global_stats(&self.connect_pool).await.map_err(|error| {
                DbError::Internal(format!(
                    "failed to query persistent connect global stats cache: {}",
                    error
                ))
            })
        }
    }

    async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        match sqlite::dns::query_dns_history(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns history: {}", error);
                DnsHistoryResponse::default()
            }
        }
    }

    async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        match sqlite::dns::query_dns_summary(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns summary: {}", error);
                DnsSummaryResponse::default()
            }
        }
    }

    async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        match sqlite::dns::query_dns_lightweight_summary(&self.dns_pool, params).await {
            Ok(response) => response,
            Err(error) => {
                tracing::error!("failed to query persistent dns lightweight summary: {}", error);
                DnsLightweightSummaryResponse::default()
            }
        }
    }

    async fn get_dns_summary_parts(
        &self,
        start_ms: u64,
        end_ms: u64,
        flow_id: Option<u32>,
    ) -> DnsSummaryParts {
        match sqlite::dns::query_dns_summary_parts(&self.dns_pool, start_ms, end_ms, flow_id).await
        {
            Ok(parts) => parts,
            Err(error) => {
                tracing::error!("failed to query persistent dns summary parts: {}", error);
                DnsSummaryParts::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::metric::connect::{ConnectMetric, ConnectStatusType};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn test_config() -> MetricRuntimeConfig {
        MetricRuntimeConfig {
            mode: landscape_common::config::MetricMode::Persistent,
            connect_second_window_minutes: 5,
            connect_1m_retention_days: 1,
            connect_1h_retention_days: 7,
            connect_1d_retention_days: 30,
            connect_summary_retention_days: 30,
            connect_summary_max_rows: 0,
            connect_db_max_bytes: landscape_common::DEFAULT_METRIC_CONNECT_DB_MAX_BYTES,
            dns_retention_days: 7,
            dns_1m_retention_days: 30,
            dns_db_max_bytes: landscape_common::DEFAULT_DNS_METRIC_DB_MAX_BYTES,
            write_batch_size: 16,
            write_flush_interval_secs: 1,
            cleanup_interval_secs: 3600,
            cleanup_time_budget_ms: 1_000,
            cleanup_slice_window_secs: 60,
        }
    }

    fn test_metric(
        create_time: u64,
        cpu_id: u32,
        report_time: u64,
        ingress_bytes: u64,
    ) -> ConnectMetric {
        ConnectMetric::from_domain(
            create_time,
            cpu_id,
            report_time,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            10_000 + cpu_id as u16,
            20_000 + cpu_id as u16,
            cpu_id as u8,
            cpu_id as u8,
            cpu_id + 10,
            ingress_bytes,
            ingress_bytes / 10,
            ingress_bytes * 2,
            ingress_bytes / 5,
            ConnectStatusType::Active,
        )
    }

    /// cleanup_connect 应检测到 global stats 缓存过期并后台重建,
    /// 重建结果必须与 conn_summaries 全表聚合一致(含绕过缓存的直接 SQL 写入)。
    #[tokio::test]
    async fn cleanup_connect_rebuilds_stale_global_stats_cache() {
        let temp = tempfile::tempdir().unwrap();
        let store = PersistentMetricStore::new(temp.path().to_path_buf()).await.unwrap();
        let pool = store.connect_pool.clone();
        let now_ms = get_current_time_ms().unwrap();

        // 1. 经 sink 写入一条 summary(缓存同步更新)。
        let mut batch = Batch::default();
        batch.push_summary(test_metric(1_000, 1, now_ms - 2_000, 100));
        assert!(store.apply_connect_batch(&batch).await);

        // 2. 直接 SQL 再插入一条 summary(绕过缓存,制造漂移)。
        sqlx::query(
            "INSERT INTO conn_summaries (
                create_time, cpu_id, src_ip, dst_ip, src_port, dst_port, l4_proto, l3_proto,
                flow_id, trace_id, ifindex, last_report_time,
                total_ingress_bytes, total_egress_bytes, total_ingress_pkts, total_egress_pkts,
                status, create_time_ms, gress
            ) VALUES (2_000, 2, '10.0.0.2', '10.0.1.2', 30_000, 40_000, 6, 4, 2, 2, 12,
                ?1, 300, 600, 30, 60, 2, 2_000, 0)",
        )
        .bind(now_ms as i64)
        .execute(&pool)
        .await
        .unwrap();

        // 3. 缓存标记为从未计算(0),强制 cleanup 判定过期。
        sqlx::query(
            "UPDATE conn_global_stats_cache
             SET last_calculate_time = 0, total_connect_count = 0, total_ingress_bytes = 0",
        )
        .execute(&pool)
        .await
        .unwrap();

        // 4. cleanup_connect 应触发后台重建。
        store.cleanup_connect(&test_config()).await;

        // 5. 轮询等待重建完成,断言缓存与全表聚合一致。
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let stats = loop {
            let stats = store.get_global_stats(false).await.unwrap();
            if stats.total_connect_count >= 2 {
                break stats;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for global stats rebuild"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        assert_eq!(stats.total_connect_count, 2);
        assert_eq!(stats.total_ingress_bytes, 400);
        assert_eq!(stats.total_egress_bytes, 800);
        assert!(stats.last_calculate_time > 0, "rebuild must refresh last_calculate_time");

        // 6. 重建后的缓存不再判为过期,后续 cleanup 不重复触发(句柄回收路径无 panic)。
        store.cleanup_connect(&test_config()).await;
        let stats = store.get_global_stats(false).await.unwrap();
        assert_eq!(stats.total_connect_count, 2);
        assert_eq!(stats.total_ingress_bytes, 400);

        store.close().await;
    }

    /// 数据库满(SQLITE_FULL)时,写入路径应触发热回收(删最旧 + 压缩)并重试成功,
    /// 而不是持续丢批直到下一轮 cleanup 腾出空间。
    #[tokio::test]
    async fn sqlite_full_triggers_hot_reclaim_and_retry_succeeds() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = test_config();
        config.connect_db_max_bytes = 1024 * 1024;
        let store = PersistentMetricStore::new_with_config(temp.path().to_path_buf(), &config)
            .await
            .unwrap();

        // 写入量远超 1MB 上限:中途必然触达 max_page_count 而 SQLITE_FULL,
        // 每次 apply 都必须经"热回收 + 重试一次"成功返回 true。
        let mut total_written = 0u64;
        for round in 0..60u32 {
            let mut batch = Batch::default();
            for i in 0..300u32 {
                let create_time = round as u64 * 10_000 + i as u64;
                batch.push_summary(test_metric(create_time, 1, create_time, 100));
            }
            assert!(
                store.apply_connect_batch(&batch).await,
                "round {round} must be written via hot reclaim"
            );
            total_written += batch.summary_metrics.len() as u64;
        }

        // 容量强制确实发生过删除:库内行数少于累计写入量,且非空。
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM conn_summaries")
            .fetch_one(&store.connect_pool)
            .await
            .unwrap();
        assert!(count > 0, "database must not be fully emptied");
        assert!(
            (count as u64) < total_written,
            "hot reclaim must have deleted oldest rows (count={count}, written={total_written})"
        );

        store.close().await;
    }
}
