use std::path::PathBuf;
use std::sync::Arc;

use std::time::Duration;

use landscape_common::{
    LANDSCAPE_METRIC_DIR_NAME,
    concurrency::{spawn_task, task_label},
    database::error::DbError,
    memtrack::MemorySeriesResponse,
    metric::connect::{
        ConnectGlobalStats, ConnectHistoryQueryParams, ConnectHistoryResponse, ConnectKey,
        ConnectMetricPoint, ConnectRealtimeStatus, IfaceRealtimeStat, IpHistoryStat,
        IpRealtimeStat, MetricResolution,
    },
    metric::dns::DnsMetricReporter,
    metric::dns::{
        DnsHistoryQueryParams, DnsHistoryResponse, DnsLightweightSummaryResponse, DnsLiveDashboard,
        DnsSummaryQueryParams, DnsSummaryResponse,
    },
    self_monitor::memory::{MemHistoryQueryParams, MemHistoryResponse},
    service::ServiceStatus,
    sys_config::{ConnectMetricRuntimeConfig, DnsMetricRuntimeConfig, SelfMonitorRuntimeConfig},
};
use landscape_ebpf::metric::MetricSourceFactory;
use tokio::sync::{Mutex, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub mod memory_store {
    pub use landscape_metric::MemoryMetricStore;
}

mod connect;
mod dns;
mod self_monitor;
mod state;
mod supervisor;

use connect::ConnectMetricService;
use dns::DnsMetricService;
use self_monitor::SelfMonitorService;
use supervisor::MetricComponent;

const STOP_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);

struct MetricRun {
    stop: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for MetricRun {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

impl MetricRun {
    async fn join(&mut self) -> Result<(), tokio::time::error::Elapsed> {
        // Keep unfinished handles on timeout so the next start waits for the same workers.
        tokio::time::timeout(STOP_TIMEOUT, async {
            while let Some(task) = self.tasks.last_mut() {
                if let Err(error) = task.await {
                    tracing::error!(%error, "metric supervisor exited");
                }
                self.tasks.pop();
            }
        })
        .await
    }
}

#[derive(Clone)]
pub struct MetricService {
    connect: Arc<ConnectMetricService>,
    dns: Arc<DnsMetricService>,
    self_monitor: Arc<SelfMonitorService>,
    run: Arc<Mutex<Option<MetricRun>>>,
}

impl MetricService {
    pub fn new(
        home_path: PathBuf,
        connect: watch::Receiver<ConnectMetricRuntimeConfig>,
        dns: watch::Receiver<DnsMetricRuntimeConfig>,
        self_monitor: watch::Receiver<SelfMonitorRuntimeConfig>,
        source_factory: Arc<dyn MetricSourceFactory>,
    ) -> Self {
        let path = home_path.join(LANDSCAPE_METRIC_DIR_NAME);
        Self {
            connect: Arc::new(ConnectMetricService::new(path.clone(), connect, source_factory)),
            dns: Arc::new(DnsMetricService::new(path, dns)),
            self_monitor: Arc::new(SelfMonitorService::new(home_path, self_monitor)),
            run: Arc::new(Mutex::new(None)),
        }
    }
    pub fn dns_metric_reporter(&self) -> DnsMetricReporter {
        self.dns.reporter.clone()
    }

    pub fn status(&self) -> ServiceStatus {
        let states = [self.connect.status(), self.dns.status(), self.self_monitor.status.current()];
        [
            ServiceStatus::Failed,
            ServiceStatus::Stopping,
            ServiceStatus::Staring,
            ServiceStatus::Running,
        ]
        .into_iter()
        .find(|s| states.contains(s))
        .unwrap_or(ServiceStatus::Stop)
    }

    pub async fn start_service(&self) -> Result<(), tokio::time::error::Elapsed> {
        let mut slot = self.run.lock().await;
        if let Some(run) = slot.as_mut() {
            if !run.stop.is_cancelled() && run.tasks.iter().any(|task| !task.is_finished()) {
                return Ok(());
            }
            run.join().await?;
        }
        let stop = CancellationToken::new();
        let (connect_tx, connect_rx) = oneshot::channel();
        let (dns_tx, dns_rx) = oneshot::channel();
        let connect = self.connect.clone();
        let dns = self.dns.clone();
        let monitor = self.self_monitor.clone();
        let (monitor_tx, monitor_rx) = oneshot::channel();
        let connect_stop = stop.clone();
        let dns_stop = stop.clone();
        let monitor_stop = stop.clone();
        let tasks = vec![
            spawn_task(task_label::task::METRIC_CONNECT_SERVICE, async move {
                connect.supervise(&connect_stop, connect_tx).await
            }),
            spawn_task(task_label::task::METRIC_DNS_SERVICE, async move {
                dns.supervise(&dns_stop, dns_tx).await
            }),
            spawn_task(task_label::task::MEM_SAMPLE, async move {
                monitor.run(&monitor_stop, monitor_tx).await
            }),
        ];
        *slot = Some(MetricRun { stop, tasks });
        drop(slot);
        let _ = tokio::join!(connect_rx, dns_rx, monitor_rx);
        Ok(())
    }

    pub async fn stop_service(&self) -> Result<(), tokio::time::error::Elapsed> {
        let mut slot = self.run.lock().await;
        if let Some(run) = slot.as_mut() {
            run.stop.cancel();
            run.join().await?;
            *slot = None;
        }
        Ok(())
    }
    pub async fn connect_infos(&self) -> Vec<ConnectRealtimeStatus> {
        self.connect.engine().connect_infos().await
    }

    pub async fn get_realtime_ip_stats(&self, is_src: bool) -> Vec<IpRealtimeStat> {
        self.connect.engine().get_realtime_ip_stats(is_src).await
    }

    pub async fn get_realtime_iface_stats(&self) -> Vec<IfaceRealtimeStat> {
        self.connect.engine().get_realtime_iface_stats().await
    }

    pub async fn query_metric_by_key(
        &self,
        key: ConnectKey,
        resolution: MetricResolution,
    ) -> Vec<ConnectMetricPoint> {
        self.connect.engine().query_metric_by_key(key, resolution).await
    }

    pub async fn history_summaries_complex(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> ConnectHistoryResponse {
        self.connect.engine().history_summaries_complex(params).await
    }

    pub async fn history_src_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.connect.engine().history_src_ip_stats(params).await
    }

    pub async fn history_dst_ip_stats(
        &self,
        params: ConnectHistoryQueryParams,
    ) -> Vec<IpHistoryStat> {
        self.connect.engine().history_dst_ip_stats(params).await
    }

    pub async fn get_global_stats(
        &self,
        force_refresh: bool,
    ) -> Result<ConnectGlobalStats, DbError> {
        self.connect.engine().get_global_stats(force_refresh).await
    }

    pub fn get_dns_live_dashboard(&self, flow_id: Option<u32>) -> DnsLiveDashboard {
        self.dns.engine().get_dns_live_dashboard(flow_id)
    }

    pub async fn query_dns_history(&self, params: DnsHistoryQueryParams) -> DnsHistoryResponse {
        self.dns.engine().query_dns_history(params).await
    }

    pub async fn get_dns_summary(&self, params: DnsSummaryQueryParams) -> DnsSummaryResponse {
        self.dns.engine().get_dns_summary(params).await
    }

    pub async fn get_dns_lightweight_summary(
        &self,
        params: DnsSummaryQueryParams,
    ) -> DnsLightweightSummaryResponse {
        self.dns.engine().get_dns_lightweight_summary(params).await
    }

    pub fn recent_memory_series(
        &self,
        limit: usize,
        subsystem: Option<&str>,
    ) -> MemorySeriesResponse {
        self.self_monitor.history.recent_series(limit, subsystem)
    }

    pub async fn query_memory_history(&self, params: &MemHistoryQueryParams) -> MemHistoryResponse {
        self.self_monitor.query_history(params).await
    }
}

#[cfg(test)]
mod tests;
