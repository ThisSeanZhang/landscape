use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use landscape_common::{
    concurrency::{spawn_named_thread, spawn_task, task_label, thread_name},
    config::{MetricMode, MetricRuntimeConfig},
    database::error::DbError,
    event::{ConnectMessage, DnsMetricMessage},
    metric::connect::{
        ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
        ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat,
        IpRealtimeStat, MetricResolution,
    },
    metric::dns::{
        DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse,
        DnsSummaryQueryParams, DnsSummaryResponse,
    },
    service::{ServiceStatus, WatchService},
    LANDSCAPE_METRIC_DIR_NAME,
};
use landscape_metric::MetricEngine;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

pub mod memory_store {
    pub use landscape_metric::MemoryMetricStore;
}

#[derive(Clone)]
struct MetricServiceState {
    config: MetricRuntimeConfig,
    engine: MetricEngine,
}

struct MetricServiceInner {
    home_path: PathBuf,
    state: RwLock<MetricServiceState>,
    switch_lock: Mutex<()>,
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
    fn read_state(&self) -> RwLockReadGuard<'_, MetricServiceState> {
        self.inner.state.read().unwrap_or_else(|poisoned| {
            tracing::error!("metric service state lock poisoned; recovering the inner state");
            poisoned.into_inner()
        })
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, MetricServiceState> {
        self.inner.state.write().unwrap_or_else(|poisoned| {
            tracing::error!("metric service state lock poisoned; recovering the inner state");
            poisoned.into_inner()
        })
    }

    pub async fn new(home_path: PathBuf, config: MetricRuntimeConfig) -> Result<Self, String> {
        let metric_path = ensure_metric_path(&home_path);
        let engine = MetricEngine::new(metric_path, config.clone())
            .await
            .map_err(|error| format!("failed to initialize metric engine: {error}"))?;
        let status = WatchService::new();

        Ok(MetricService {
            status,
            inner: Arc::new(MetricServiceInner {
                home_path,
                state: RwLock::new(MetricServiceState { config, engine }),
                switch_lock: Mutex::new(()),
            }),
        })
    }

    fn current_engine(&self) -> MetricEngine {
        self.read_state().engine.clone()
    }

    fn current_mode(&self) -> MetricMode {
        let config = self.read_state().config.clone();
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
        self.start_service_locked().await;
    }

    async fn start_service_locked(&self) {
        if matches!(self.current_mode(), MetricMode::Off) {
            tracing::info!("Metric service disabled by mode=off");
            return;
        }

        let status = self.status.clone();
        if status.is_stop() {
            let Some(connect_msg_tx) = self.current_engine().get_connect_msg_channel() else {
                tracing::error!("metric backend did not expose a connect channel during startup");
                status.just_change_status(ServiceStatus::Failed);
                return;
            };
            status.just_change_status(ServiceStatus::Staring);
            spawn_task(task_label::task::METRIC_SERVICE_RUN, async move {
                create_metric_service(status, connect_msg_tx).await;
            });
        } else {
            tracing::info!("Metric Service is not stopped");
        }
    }

    pub async fn stop_service(&self) {
        let _guard = self.inner.switch_lock.lock().await;
        self.stop_service_locked().await;
    }

    async fn stop_service_locked(&self) {
        // 等待预算须 ≥ create_metric_service 的收尾预算(reader 退出 3s,正常路径
        // 无额外 join 等待),保证超时返回前最终状态(Stop/Failed)已经落定,配置
        // 切换后新引擎能启动 reader。
        if timeout(Duration::from_secs(10), self.status.wait_stop()).await.is_err() {
            // 超时不改状态:最终状态统一由 create_metric_service 按 reader 线程的实际
            // 结果(reader_ok && joined_ok)判定,避免这里先置 Failed 又被后续 Stop 覆盖。
            tracing::error!("timed out waiting for metric service reader to stop");
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
                    self.start_service_locked().await;
                }
                return Err(match recovery_error {
                    Some(recovery_error) => format!("{error}; {recovery_error}"),
                    None => error,
                });
            }
        };

        {
            let mut state = self.write_state();
            state.engine = new_engine;
            state.config = config;
        }

        if !matches!(self.current_mode(), MetricMode::Off) {
            self.start_service_locked().await;
        }
        Ok(())
    }

    async fn restore_previous_engine(&self) -> Result<(), String> {
        let previous_config = {
            let state = self.read_state();
            state.config.clone()
        };
        match MetricEngine::new(ensure_metric_path(&self.inner.home_path), previous_config.clone())
            .await
        {
            Ok(engine) => {
                let mut state = self.write_state();
                state.engine = engine;
                state.config = previous_config;
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
                let mut state = self.write_state();
                state.engine = fallback_engine;
                state.config = fallback_config;
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
}

pub async fn create_metric_service(
    service_status: WatchService,
    connect_msg_tx: mpsc::Sender<ConnectMessage>,
) {
    if service_status.is_exit() {
        service_status.just_change_status(ServiceStatus::Stop);
        return;
    }

    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<bool>();
    service_status.just_change_status(ServiceStatus::Running);
    let reader_result = spawn_named_thread(thread_name::fixed::METRIC_EVENT_READER, move || {
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
            landscape_ebpf::metric::new_metric(rx, connect_msg_tx);
        }));
        let reader_ok = result.is_ok();
        if !reader_ok {
            tracing::error!("metric event reader panicked; stopping metric service");
        }
        let _ = other_tx.send(reader_ok);
    });
    let reader_handle = match reader_result {
        Ok(handle) => handle,
        Err(error) => {
            tracing::error!("failed to spawn metric event thread: {}", error);
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    // 单任务接管 reader 生命周期:等待外部停止请求 → 通知 reader 退出 → 限时回收
    // 结果并落定最终状态。reader 收到停止信号后正常 1s 内退出(poll 周期 1s);
    // 即使异常卡住,也会在预算内强制给出 Stop/Failed,避免状态永久停在 Stopping
    // 导致配置切换后新引擎无法启动 reader。
    // 预算:reader 退出 3s;正常退出后 join 立即完成,不占额外预算。总预算 3s,
    // 小于 stop_service_locked 的 10s 等待,保证配置切换时最终状态已落定。
    const READER_EXIT_TIMEOUT: Duration = Duration::from_secs(3);
    let service_status_clone = service_status.clone();
    spawn_task(task_label::task::METRIC_SERVICE_STOP, async move {
        let _ = service_status_clone.wait_to_stopping().await;
        tracing::info!("Received external stop signal");
        let _ = tx.send(());

        let reader_ok = timeout(READER_EXIT_TIMEOUT, other_rx)
            .await
            .ok()
            .and_then(|result| result.ok())
            .unwrap_or_else(|| {
                tracing::error!("timed out waiting for metric event reader to exit");
                false
            });
        // reader 已正常退出时直接 join(线程已返回,join 立即完成);
        // 未正常退出(超时/panic)时**不 join、直接 detach**:Rust 线程无法强制
        // 终止,继续等待只会占住 blocking 线程池线程,卡死的 reader 在后台
        // 自生自灭(可能残留持有旧 connect channel sender 的引用,但其 poll
        // 周期 1s、对已关闭通道的 send 会失败退出,不影响新引擎)。
        let joined_ok = if reader_ok {
            match reader_handle.join() {
                Ok(()) => true,
                Err(_) => {
                    tracing::error!("metric event reader thread exited with an uncaught panic");
                    false
                }
            }
        } else {
            tracing::error!(
                "metric event reader did not exit in time ({READER_EXIT_TIMEOUT:?}); \
                 leaving the stuck thread detached and marking the service as failed"
            );
            false
        };
        tracing::info!("Worker thread exited");
        if reader_ok && joined_ok {
            service_status_clone.just_change_status(ServiceStatus::Stop);
        } else {
            service_status_clone.just_change_status(ServiceStatus::Failed);
        }
    });
}
