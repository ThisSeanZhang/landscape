use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use landscape_common::{
    config::{MetricMode, MetricRuntimeConfig},
    database::error::DbError,
    event::DnsMetricMessage,
    metric::connect::{
        ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
        ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat,
        IpRealtimeStat, MetricResolution,
    },
    metric::dns::{
        DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
        DnsSummaryQueryParams, DnsSummaryResponse,
    },
    metric::memory::{
        MemHistoryQueryParams, MemHistoryResponse, DEFAULT_MEM_METRIC_RETENTION_DAYS,
    },
    service::{ServiceStatus, WatchService},
    LANDSCAPE_METRIC_DIR_NAME,
};
use landscape_ebpf::metric::{EventSourceStopOutcome, MetricSourceFactory, MetricSourceHandle};
use landscape_metric::MetricEngine;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

pub mod memory_store {
    pub use landscape_metric::MemoryMetricStore;
}

struct MetricRuntime {
    config: MetricRuntimeConfig,
    engine: MetricEngine,
    source: Option<Box<dyn MetricSourceHandle>>,
}

struct MetricServiceInner {
    home_path: PathBuf,
    runtime: RwLock<MetricRuntime>,
    switch_lock: Mutex<()>,
    source_factory: Arc<dyn MetricSourceFactory>,
    /// 内存指标记录。非 persistent 构建下是 no-op 实现(stub),恒为 None,
    /// 因此本文件无需任何 cfg。
    mem_recording: Mutex<Option<landscape_metric::mem_store::MemRecording>>,
}

#[derive(Clone)]
pub struct MetricService {
    pub status: WatchService,
    inner: Arc<MetricServiceInner>,
}

fn ensure_metric_path(home_path: &Path) -> PathBuf {
    let metric_path = home_path.join(LANDSCAPE_METRIC_DIR_NAME);
    if !metric_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&metric_path) {
            tracing::error!("Failed to create metric directory: {}", e);
        }
    }
    metric_path
}

impl MetricService {
    fn read_runtime(&self) -> RwLockReadGuard<'_, MetricRuntime> {
        self.inner.runtime.read().unwrap_or_else(|poisoned| {
            tracing::error!("metric service runtime lock poisoned; recovering the inner state");
            poisoned.into_inner()
        })
    }

    fn write_runtime(&self) -> RwLockWriteGuard<'_, MetricRuntime> {
        self.inner.runtime.write().unwrap_or_else(|poisoned| {
            tracing::error!("metric service runtime lock poisoned; recovering the inner state");
            poisoned.into_inner()
        })
    }

    pub async fn new(
        home_path: PathBuf,
        config: MetricRuntimeConfig,
        source_factory: Arc<dyn MetricSourceFactory>,
    ) -> Result<Self, String> {
        let metric_path = ensure_metric_path(&home_path);
        let engine = MetricEngine::new(metric_path, config.clone())
            .await
            .map_err(|error| format!("failed to initialize metric engine: {error}"))?;
        let status = WatchService::new();

        Ok(MetricService {
            status,
            inner: Arc::new(MetricServiceInner {
                home_path,
                runtime: RwLock::new(MetricRuntime { config, engine, source: None }),
                switch_lock: Mutex::new(()),
                source_factory,
                mem_recording: Mutex::new(None),
            }),
        })
    }

    fn current_engine(&self) -> MetricEngine {
        self.read_runtime().engine.clone()
    }

    fn current_mode(&self) -> MetricMode {
        let config = self.read_runtime().config.clone();
        landscape_metric::resolved_metric_mode(config.mode)
    }

    pub fn get_dns_metric_channel(&self) -> Option<mpsc::Sender<DnsMetricMessage>> {
        if matches!(self.current_mode(), MetricMode::Off) {
            None
        } else {
            self.current_engine().get_dns_msg_channel()
        }
    }

    pub async fn start_service(&self) {
        let _guard = self.inner.switch_lock.lock().await;
        if let Err(error) = self.start_service_locked().await {
            tracing::error!("failed to start metric service: {error}");
        }
    }

    /// 启动流程全同步内联:模式/状态检查 → 取引擎通道 → spawn 事件源 → Running。
    /// 事件源构建失败(map 缺失等)立即落定 Failed 并返回 Err,由调用方决定
    /// 是否回滚,而非让任务 panic 后在停止时才被察觉。
    async fn start_service_locked(&self) -> Result<(), String> {
        if matches!(self.current_mode(), MetricMode::Off) {
            tracing::info!("Metric service disabled by mode=off");
            return Ok(());
        }

        let status = self.status.clone();
        if !status.is_stop() {
            tracing::info!("Metric Service is not stopped");
            return Ok(());
        }
        let Some(connect_msg_tx) = self.current_engine().get_connect_msg_channel() else {
            let error = "metric backend did not expose a connect channel during startup";
            tracing::error!("{error}");
            status.just_change_status(ServiceStatus::Failed);
            return Err(error.to_string());
        };

        status.just_change_status(ServiceStatus::Staring);
        match self.inner.source_factory.spawn(connect_msg_tx) {
            Ok(source) => {
                self.write_runtime().source = Some(source);
                status.just_change_status(ServiceStatus::Running);
                self.ensure_memory_recording().await;
                Ok(())
            }
            Err(error) => {
                tracing::error!("failed to spawn metric event source: {error}");
                status.just_change_status(ServiceStatus::Failed);
                Err(error.to_string())
            }
        }
    }

    /// 内存指标记录:仅 persistent 模式与 persistent 构建启用(非 persistent
    /// 构建下 `start_memory_recording` 恒返回 None,自然退化);打开失败或
    /// 记录任务异常都不影响 metric 主流程(历史查询返回空)。
    async fn ensure_memory_recording(&self) {
        if !matches!(self.current_mode(), MetricMode::Persistent) {
            return;
        }
        let mut mem = self.inner.mem_recording.lock().await;
        match mem.as_mut() {
            // 已打开:恢复被 stop_service 停掉的 recorder。
            Some(recording) => recording.spawn_recorder(DEFAULT_MEM_METRIC_RETENTION_DAYS),
            None => {
                let home_path = self.inner.home_path.clone();
                *mem = landscape_metric::mem_store::start_memory_recording(
                    home_path,
                    DEFAULT_MEM_METRIC_RETENTION_DAYS,
                )
                .await;
            }
        }
    }

    pub async fn stop_service(&self) {
        let _guard = self.inner.switch_lock.lock().await;
        self.stop_service_locked().await;
    }

    /// 停止流程全同步内联:置 Stopping → 回收事件源(限时 3s) → 落定
    /// Stop/Failed → 引擎收尾。事件源回收预算须小于调用方预期,保证配置
    /// 切换时最终状态已落定、新引擎能立即启动新事件源。
    async fn stop_service_locked(&self) {
        const EVENT_SOURCE_EXIT_TIMEOUT: Duration = Duration::from_secs(3);

        // 仅在服务真的在运行/启动中时才先经过 Stopping,避免对已处于
        // Stop/Failed 的服务(如从未启动)产生无效状态转换的告警噪音。
        if self.status.is_active() {
            self.status.just_change_status(ServiceStatus::Stopping);
        }
        let source = self.write_runtime().source.take();
        let outcome = match source {
            Some(source) => source.stop_with_budget(EVENT_SOURCE_EXIT_TIMEOUT).await,
            None => {
                tracing::debug!("no metric event source to stop");
                EventSourceStopOutcome::Clean
            }
        };
        let final_status = match outcome {
            EventSourceStopOutcome::Clean => ServiceStatus::Stop,
            EventSourceStopOutcome::Panicked | EventSourceStopOutcome::Aborted => {
                ServiceStatus::Failed
            }
        };
        if self.status.current() != final_status {
            self.status.just_change_status(final_status);
        }
        // 停止内存指标记录(收尾写入当前分钟);store 保留供历史查询,
        // 下次 start_service 时 recorder 会被重新拉起。
        {
            let mut mem = self.inner.mem_recording.lock().await;
            if let Some(recording) = mem.as_mut() {
                recording.stop_recorder().await;
            }
        }
        self.current_engine().shutdown().await;
    }

    pub async fn apply_runtime_config(&self, config: MetricRuntimeConfig) -> Result<(), String> {
        let _guard = self.inner.switch_lock.lock().await;

        self.stop_service_locked().await;

        let new_engine = match MetricEngine::new(
            ensure_metric_path(&self.inner.home_path),
            config.clone(),
        )
        .await
        {
            Ok(engine) => engine,
            Err(error) => {
                tracing::error!(
                    "failed to rebuild metric engine for new config, restoring previous config: {}",
                    error
                );
                let recovery_error = self.restore_previous_engine().await.err();
                if !matches!(self.current_mode(), MetricMode::Off) {
                    if let Err(start_error) = self.start_service_locked().await {
                        tracing::error!(
                            "failed to restart metric service after engine rebuild failure: {start_error}"
                        );
                    }
                }
                return Err(match recovery_error {
                    Some(recovery_error) => format!("{error}; {recovery_error}"),
                    None => error,
                });
            }
        };

        {
            let mut runtime = self.write_runtime();
            runtime.engine = new_engine;
            runtime.config = config;
        }

        if !matches!(self.current_mode(), MetricMode::Off) {
            self.start_service_locked().await?;
        }
        Ok(())
    }

    async fn restore_previous_engine(&self) -> Result<(), String> {
        let previous_config = {
            let runtime = self.read_runtime();
            runtime.config.clone()
        };
        match MetricEngine::new(ensure_metric_path(&self.inner.home_path), previous_config.clone())
            .await
        {
            Ok(engine) => {
                let mut runtime = self.write_runtime();
                runtime.engine = engine;
                runtime.config = previous_config;
                Ok(())
            }
            Err(error) => {
                tracing::error!("failed to restore metric engine with previous config: {}", error);
                let mut fallback_config = previous_config;
                fallback_config.mode = MetricMode::Memory;
                let fallback_engine = MetricEngine::new(
                    ensure_metric_path(&self.inner.home_path),
                    fallback_config.clone(),
                )
                .await
                .map_err(|fallback_error| {
                    format!(
                        "failed to restore previous metric engine: {error}; failed to start memory fallback: {fallback_error}"
                    )
                })?;
                let mut runtime = self.write_runtime();
                runtime.engine = fallback_engine;
                runtime.config = fallback_config;
                Err(format!(
                    "failed to restore previous metric engine: {error}; running memory fallback"
                ))
            }
        }
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        self.current_engine().connect_infos().await
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        self.current_engine().get_realtime_ip_stats(is_src).await
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        self.current_engine().get_realtime_iface_stats().await
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        self.current_engine().query_metric_by_key(key, resolution).await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> ConnectHistoryResponse {
        self.current_engine().history_summaries_complex(params).await
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.current_engine().history_src_ip_stats(params).await
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.current_engine().history_dst_ip_stats(params).await
    }

    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        self.current_engine().get_global_stats(force_refresh).await
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        self.current_engine().query_dns_history(params).await
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        self.current_engine().get_dns_summary(params).await
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        self.current_engine().get_dns_lightweight_summary(params).await
    }

    /// 已持久化的内存指标分钟历史(persistent 构建;未启用/无数据返回空)。
    /// 最近实时数据走 `/api/v1/system/memory` 的 RAM 环形缓冲,互不串门。
    pub async fn query_memory_history(&self, params: MemHistoryQueryParams) -> MemHistoryResponse {
        let mem = self.inner.mem_recording.lock().await;
        match mem.as_ref() {
            Some(recording) => recording.query_history(&params).await,
            None => MemHistoryResponse::default(),
        }
    }
}
