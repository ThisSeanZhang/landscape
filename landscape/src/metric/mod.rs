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
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex;

#[cfg(feature = "metric-duckdb")]
pub mod duckdb;
pub mod memory_store;

#[derive(Clone)]
enum MetricBackend {
    Off,
    Memory(memory_store::MemoryMetricStore),
    #[cfg(feature = "metric-duckdb")]
    Duckdb(duckdb::DuckMetricStore),
}

impl MetricBackend {
    async fn new(base_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        #[cfg(feature = "metric-duckdb")]
        {
            match resolved_metric_mode(config.mode.clone()) {
                MetricMode::Off => Self::Off,
                MetricMode::Memory => {
                    tracing::info!("metric mode=memory, using in-memory realtime backend");
                    Self::Memory(memory_store::MemoryMetricStore::new(base_path, config).await)
                }
                MetricMode::Duckdb => {
                    match duckdb::DuckMetricStore::new(base_path.clone(), config.clone()).await {
                        Ok(store) => Self::Duckdb(store),
                        Err(error) => {
                            tracing::error!(
                            "failed to initialize duckdb metric backend, falling back to memory: {}",
                            error
                        );
                            Self::Memory(
                                memory_store::MemoryMetricStore::new(base_path, config).await,
                            )
                        }
                    }
                }
            }
        }

        #[cfg(not(feature = "metric-duckdb"))]
        {
            match resolved_metric_mode(config.mode.clone()) {
                MetricMode::Off => Self::Off,
                MetricMode::Memory | MetricMode::Duckdb => {
                    if matches!(config.mode, MetricMode::Duckdb) {
                        tracing::warn!(
                            "metric mode 'duckdb' requested without metric-duckdb feature, falling back to memory"
                        );
                    } else {
                        tracing::info!("metric mode=memory, using in-memory realtime backend");
                    }
                    Self::Memory(memory_store::MemoryMetricStore::new(base_path, config).await)
                }
            }
        }
    }

    fn shutdown(&self) {
        match self {
            Self::Off => {}
            Self::Memory(store) => store.shutdown(),
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.shutdown(),
        }
    }

    fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        match self {
            Self::Off => unreachable!("off metric backend does not expose connect channel"),
            Self::Memory(store) => store.get_connect_msg_channel(),
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.get_connect_msg_channel(),
        }
    }

    fn get_dns_msg_channel(&self) -> mpsc::Sender<DnsMetricMessage> {
        match self {
            Self::Off => unreachable!("off metric backend does not expose dns channel"),
            Self::Memory(store) => store.get_dns_msg_channel(),
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.get_dns_msg_channel(),
        }
    }

    async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.connect_infos().await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.connect_infos().await,
        }
    }

    async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.get_realtime_ip_stats(is_src).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.get_realtime_ip_stats(is_src).await,
        }
    }

    async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.get_realtime_iface_stats().await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.get_realtime_iface_stats().await,
        }
    }

    async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.query_metric_by_key(key, resolution).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.query_metric_by_key(key, resolution).await,
        }
    }

    async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.history_summaries_complex(params).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.history_summaries_complex(params).await,
        }
    }

    async fn history_src_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.history_src_ip_stats(params).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.history_src_ip_stats(params).await,
        }
    }

    async fn history_dst_ip_stats(&self, params: ConnectHistoryQueryParams) -> Vec<IpHistoryStat> {
        match self {
            Self::Off => Vec::new(),
            Self::Memory(store) => store.history_dst_ip_stats(params).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.history_dst_ip_stats(params).await,
        }
    }

    async fn get_global_stats(&self, force_refresh: bool) -> Result<ConnectGlobalStats, DbError> {
        match self {
            Self::Off => Ok(ConnectGlobalStats::default()),
            Self::Memory(store) => store.get_global_stats(force_refresh).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.get_global_stats(force_refresh).await,
        }
    }

    async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        match self {
            Self::Off => DnsHistoryResponse::default(),
            Self::Memory(store) => store.query_dns_history(params).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.query_dns_history(params).await,
        }
    }

    async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        match self {
            Self::Off => DnsSummaryResponse::default(),
            Self::Memory(store) => store.get_dns_summary(params).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.get_dns_summary(params).await,
        }
    }

    async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        match self {
            Self::Off => DnsLightweightSummaryResponse::default(),
            Self::Memory(store) => store.get_dns_lightweight_summary(params).await,
            #[cfg(feature = "metric-duckdb")]
            Self::Duckdb(store) => store.get_dns_lightweight_summary(params).await,
        }
    }
}

#[derive(Clone)]
struct MetricServiceState {
    config: MetricRuntimeConfig,
    store: MetricBackend,
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

fn resolved_metric_mode(mode: MetricMode) -> MetricMode {
    #[cfg(feature = "metric-duckdb")]
    {
        mode
    }

    #[cfg(not(feature = "metric-duckdb"))]
    {
        if matches!(mode, MetricMode::Duckdb) {
            MetricMode::Memory
        } else {
            mode
        }
    }
}

impl MetricService {
    pub async fn new(home_path: PathBuf, config: MetricRuntimeConfig) -> Self {
        let metric_path = ensure_metric_path(&home_path);
        let store = MetricBackend::new(metric_path, config.clone()).await;
        let status = WatchService::new();

        MetricService {
            status,
            inner: Arc::new(MetricServiceInner {
                home_path,
                state: RwLock::new(MetricServiceState { config, store }),
                switch_lock: Mutex::new(()),
            }),
        }
    }

    fn current_backend(&self) -> MetricBackend {
        self.inner.state.read().expect("metric service state poisoned").store.clone()
    }

    fn current_mode(&self) -> MetricMode {
        let config = self.inner.state.read().expect("metric service state poisoned").config.clone();
        resolved_metric_mode(config.mode)
    }

    fn get_connect_msg_channel(&self) -> mpsc::Sender<ConnectMessage> {
        self.current_backend().get_connect_msg_channel()
    }

    pub fn get_dns_metric_channel(&self) -> Option<mpsc::Sender<DnsMetricMessage>> {
        (!matches!(self.current_mode(), MetricMode::Off))
            .then(|| self.current_backend().get_dns_msg_channel())
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
    }

    pub async fn apply_runtime_config(&self, config: MetricRuntimeConfig) {
        let _guard = self.inner.switch_lock.lock().await;
        self.stop_service().await;

        let new_store =
            MetricBackend::new(ensure_metric_path(&self.inner.home_path), config.clone()).await;
        let old_store = {
            let mut state = self.inner.state.write().expect("metric service state poisoned");
            let old_store = std::mem::replace(&mut state.store, new_store);
            state.config = config;
            old_store
        };
        old_store.shutdown();

        if !matches!(self.current_mode(), MetricMode::Off) {
            self.start_service().await;
        }
    }

    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        self.current_backend().connect_infos().await
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        self.current_backend().get_realtime_ip_stats(is_src).await
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        self.current_backend().get_realtime_iface_stats().await
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        self.current_backend().query_metric_by_key(key, resolution).await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<ConnectHistoryStatus> {
        self.current_backend().history_summaries_complex(params).await
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.current_backend().history_src_ip_stats(params).await
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.current_backend().history_dst_ip_stats(params).await
    }

    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        self.current_backend().get_global_stats(force_refresh).await
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        self.current_backend().query_dns_history(params).await
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        self.current_backend().get_dns_summary(params).await
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        self.current_backend().get_dns_lightweight_summary(params).await
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
