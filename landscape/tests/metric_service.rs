use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use landscape::metric::MetricService;
use landscape_common::config::{MetricMode, MetricRuntimeConfig};
use landscape_common::event::ConnectMessage;
use landscape_common::service::ServiceStatus;
use landscape_common::{DEFAULT_DNS_METRIC_DB_MAX_BYTES, DEFAULT_METRIC_CONNECT_DB_MAX_BYTES};
use landscape_ebpf::metric::{EventSourceStopOutcome, MetricSourceFactory, MetricSourceHandle};
use tokio::sync::mpsc;

fn memory_config() -> MetricRuntimeConfig {
    MetricRuntimeConfig {
        mode: MetricMode::Memory,
        connect_second_window_minutes: 5,
        connect_1m_retention_days: 1,
        connect_1h_retention_days: 7,
        connect_1d_retention_days: 30,
        connect_summary_retention_days: 30,
        connect_summary_max_rows: 0,
        connect_db_max_bytes: DEFAULT_METRIC_CONNECT_DB_MAX_BYTES,
        dns_retention_days: 7,
        dns_1m_retention_days: 30,
        dns_db_max_bytes: DEFAULT_DNS_METRIC_DB_MAX_BYTES,
        write_batch_size: 2,
        write_flush_interval_secs: 1,
        cleanup_interval_secs: 3600,
        cleanup_time_budget_ms: 1_000,
        cleanup_slice_window_secs: 60,
    }
}

fn off_config() -> MetricRuntimeConfig {
    let mut config = memory_config();
    config.mode = MetricMode::Off;
    config
}

#[derive(Default)]
struct FakeSourceFactoryState {
    spawn_count: AtomicUsize,
    spawn_fail: AtomicBool,
    outcome: Mutex<EventSourceStopOutcome>,
    /// 构造 fake 句柄时的停止停留时长,制造 Stopping 中间态观测窗口。
    stop_delay: Mutex<Duration>,
}

#[derive(Clone)]
struct FakeSourceFactory {
    state: Arc<FakeSourceFactoryState>,
}

impl FakeSourceFactory {
    fn new() -> Self {
        FakeSourceFactory { state: Arc::new(FakeSourceFactoryState::default()) }
    }
}

impl MetricSourceFactory for FakeSourceFactory {
    fn spawn(
        &self,
        _connect_msg_tx: mpsc::Sender<ConnectMessage>,
    ) -> Result<Box<dyn MetricSourceHandle>, String> {
        self.state.spawn_count.fetch_add(1, Ordering::SeqCst);
        if self.state.spawn_fail.load(Ordering::SeqCst) {
            return Err("fake spawn failure".to_string());
        }
        let outcome = *self.state.outcome.lock().unwrap();
        let stop_delay = *self.state.stop_delay.lock().unwrap();
        Ok(Box::new(FakeSourceHandle {
            outcome,
            stop_delay,
            stopped: Arc::new(AtomicBool::new(false)),
        }))
    }
}

struct FakeSourceHandle {
    outcome: EventSourceStopOutcome,
    stop_delay: Duration,
    stopped: Arc<AtomicBool>,
}

#[async_trait]
impl MetricSourceHandle for FakeSourceHandle {
    fn request_stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
    }

    async fn stop_with_budget(self: Box<Self>, _budget: Duration) -> EventSourceStopOutcome {
        self.stopped.store(true, Ordering::SeqCst);
        if !self.stop_delay.is_zero() {
            tokio::time::sleep(self.stop_delay).await;
        }
        self.outcome
    }
}

async fn service_with(factory: &FakeSourceFactory) -> MetricService {
    let dir = tempfile::tempdir().expect("create temp dir");
    MetricService::new(dir.path().to_path_buf(), memory_config(), Arc::new(factory.clone()))
        .await
        .expect("build metric service")
}

fn status(service: &MetricService) -> ServiceStatus {
    service.status.current()
}

#[tokio::test]
async fn start_service_reaches_running() {
    let factory = FakeSourceFactory::new();
    let service = service_with(&factory).await;

    service.start_service().await;

    assert_eq!(status(&service), ServiceStatus::Running);
    assert_eq!(factory.state.spawn_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn start_service_is_idempotent_when_already_running() {
    let factory = FakeSourceFactory::new();
    let service = service_with(&factory).await;

    service.start_service().await;
    service.start_service().await;

    assert_eq!(status(&service), ServiceStatus::Running);
    assert_eq!(factory.state.spawn_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn spawn_failure_lands_failed_immediately() {
    let factory = FakeSourceFactory::new();
    factory.state.spawn_fail.store(true, Ordering::SeqCst);
    let service = service_with(&factory).await;

    service.start_service().await;

    assert_eq!(status(&service), ServiceStatus::Failed);
}

#[tokio::test]
async fn stop_service_passes_stopping_and_lands_stop() {
    let factory = FakeSourceFactory::new();
    *factory.state.stop_delay.lock().unwrap() = Duration::from_millis(100);
    let service = service_with(&factory).await;
    service.start_service().await;
    assert_eq!(status(&service), ServiceStatus::Running);

    let stop = service.stop_service();
    tokio::pin!(stop);
    let mut saw_stopping = false;
    loop {
        let done = tokio::select! {
            _ = &mut stop => true,
            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                if status(&service) == ServiceStatus::Stopping {
                    saw_stopping = true;
                }
                false
            }
        };
        if done {
            break;
        }
    }

    assert!(saw_stopping, "stop must pass through the Stopping state");
    assert_eq!(status(&service), ServiceStatus::Stop);
}

#[tokio::test]
async fn aborted_source_stop_lands_failed() {
    let factory = FakeSourceFactory::new();
    *factory.state.outcome.lock().unwrap() = EventSourceStopOutcome::Aborted;
    let service = service_with(&factory).await;
    service.start_service().await;

    service.stop_service().await;

    assert_eq!(status(&service), ServiceStatus::Failed);
}

#[tokio::test]
async fn apply_runtime_config_restarts_source_with_new_engine() {
    let factory = FakeSourceFactory::new();
    let service = service_with(&factory).await;
    service.start_service().await;
    assert_eq!(factory.state.spawn_count.load(Ordering::SeqCst), 1);

    service.apply_runtime_config(memory_config()).await.expect("apply runtime config");

    assert_eq!(status(&service), ServiceStatus::Running);
    assert_eq!(
        factory.state.spawn_count.load(Ordering::SeqCst),
        2,
        "source must be rebuilt alongside the new engine"
    );
}

#[tokio::test]
async fn mode_off_start_is_noop() {
    let factory = FakeSourceFactory::new();
    let dir = tempfile::tempdir().expect("create temp dir");
    let service =
        MetricService::new(dir.path().to_path_buf(), off_config(), Arc::new(factory.clone()))
            .await
            .expect("build metric service");

    service.start_service().await;

    assert_eq!(status(&service), ServiceStatus::Stop);
    assert_eq!(factory.state.spawn_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn switch_to_off_stops_source() {
    let factory = FakeSourceFactory::new();
    let service = service_with(&factory).await;
    service.start_service().await;
    assert_eq!(factory.state.spawn_count.load(Ordering::SeqCst), 1);

    service.apply_runtime_config(off_config()).await.expect("switch to off");

    assert_eq!(status(&service), ServiceStatus::Stop);
    assert_eq!(
        factory.state.spawn_count.load(Ordering::SeqCst),
        1,
        "switching to off must not spawn a new source"
    );
}

#[tokio::test]
async fn stop_failed_service_resets_to_stop_and_restarts() {
    let factory = FakeSourceFactory::new();
    factory.state.spawn_fail.store(true, Ordering::SeqCst);
    let service = service_with(&factory).await;
    service.start_service().await;
    assert_eq!(status(&service), ServiceStatus::Failed);

    factory.state.spawn_fail.store(false, Ordering::SeqCst);
    service.stop_service().await;
    assert_eq!(status(&service), ServiceStatus::Stop, "stopping a Failed service lands on Stop");

    service.start_service().await;
    assert_eq!(status(&service), ServiceStatus::Running);
    assert_eq!(factory.state.spawn_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn restart_after_stop_cycle() {
    let factory = FakeSourceFactory::new();
    let service = service_with(&factory).await;

    service.start_service().await;
    assert_eq!(status(&service), ServiceStatus::Running);

    service.stop_service().await;
    assert_eq!(status(&service), ServiceStatus::Stop);

    service.start_service().await;
    assert_eq!(status(&service), ServiceStatus::Running);
    assert_eq!(factory.state.spawn_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn apply_runtime_config_propagates_start_failure() {
    let factory = FakeSourceFactory::new();
    let service = service_with(&factory).await;
    service.start_service().await;
    assert_eq!(status(&service), ServiceStatus::Running);

    factory.state.spawn_fail.store(true, Ordering::SeqCst);
    let result = service.apply_runtime_config(memory_config()).await;

    assert!(result.is_err(), "start failure after engine rebuild must surface as Err");
    assert_eq!(status(&service), ServiceStatus::Failed);
}
