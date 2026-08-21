use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use landscape_common::{
    concurrency::{spawn_named_thread, spawn_task, task_label, thread_name},
    config::{MetricMode, MetricRuntimeConfig},
    database::error::DbError,
    event::{ConnectMessage, DnsMetricMessage},
    metric::connect::{
        ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryStatus, ConnectKey,
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

pub mod memory_store {
    pub use landscape_metric::MemoryMetricStore;
}

#[cfg(feature = "metric-duckdb")]
pub mod duckdb {
    pub use landscape_metric::DuckMetricStore;
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
    pub async fn new(home_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let metric_path = ensure_metric_path(&home_path);
        let engine = MetricEngine::new(metric_path, config.clone()).await;
        let status = WatchService::new();

        MetricService {
            status,
            inner: Arc::new(MetricServiceInner {
                home_path,
                state: RwLock::new(MetricServiceState { config, engine }),
                switch_lock: Mutex::new(()),
            }),
        }
    }

    fn current_engine(&self) -> MetricEngine {
        self.inner.state.read().expect("metric service state poisoned").engine.clone()
    }

    fn current_mode(&self) -> MetricMode {
        let config = self.inner.state.read().expect("metric service state poisoned").config.clone();
        landscape_metric::resolved_metric_mode(config.mode)
    }

    fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        self.current_engine()
            .get_connect_msg_channel()
            .expect("off metric backend does not expose connect channel")
    }

    pub fn get_dns_metric_channel(&self) -> Option<mpsc::Sender<DnsMetricMessage>> {
        if matches!(self.current_mode(), MetricMode::Off) {
            None
        } else {
            self.current_engine().get_dns_msg_channel()
        }
    }

    pub async fn start_service(&self) {
        if matches!(self.current_mode(), MetricMode::Off) {
            tracing::info!("Metric service disabled by mode=off");
            return;
        }

        let status = self.status.clone();
        if status.is_stop() {
            let metric_service = self.clone();
            spawn_task(task_label::task::METRIC_SERVICE_RUN, async move {
                create_metric_service(metric_service, status).await;
            });
        } else {
            tracing::info!("Metric Service is not stopped");
        }
    }

    pub async fn stop_service(&self) {
        self.status.wait_stop().await;
        self.current_engine().shutdown();
    }

    pub async fn apply_runtime_config(&self, config: MetricRuntimeConfig) {
        let _guard = self.inner.switch_lock.lock().await;
        self.stop_service().await;

        let new_engine =
            MetricEngine::new(ensure_metric_path(&self.inner.home_path), config.clone()).await;
        let old_engine = {
            let mut state = self.inner.state.write().expect("metric service state poisoned");
            let old_engine = std::mem::replace(&mut state.engine, new_engine);
            state.config = config;
            old_engine
        };
        old_engine.shutdown();

        if !matches!(self.current_mode(), MetricMode::Off) {
            self.start_service().await;
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
    ) -> Vec<ConnectHistoryStatus> {
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

pub async fn create_metric_service(metric_service: MetricService, service_status: WatchService) {
    service_status.just_change_status(ServiceStatus::Staring);
    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();
    service_status.just_change_status(ServiceStatus::Running);
    let service_status_clone = service_status.clone();
    spawn_task(task_label::task::METRIC_SERVICE_STOP, async move {
        let stop_wait = service_status_clone.wait_to_stopping();
        tracing::info!("Waiting for external stop signal");
        let _ = stop_wait.await;
        tracing::info!("Received external stop signal");
        let _ = tx.send(());
        tracing::info!("Sent internal stop signal");
    });

    let connect_msg_tx = metric_service.get_connect_msg_channel();
    spawn_named_thread(thread_name::fixed::METRIC_EVENT_READER, move || {
        landscape_ebpf::metric::new_metric(rx, connect_msg_tx);
        let _ = other_tx.send(());
    })
    .expect("failed to spawn metric event thread");
    let _ = other_rx.await;
    tracing::info!("Worker thread exited");
    service_status.just_change_status(ServiceStatus::Stop);
}
