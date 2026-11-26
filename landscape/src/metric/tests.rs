use super::*;
use landscape_ebpf::metric::{EventSourceStopOutcome, MetricSourceHandle};
use std::sync::{
    Mutex as StdMutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use hickory_proto::{op::ResponseCode, rr::RecordType};
use landscape_common::metric::{
    connect::ConnectMetric,
    dns::{DnsMetricEvent, DnsOutcome},
};
use landscape_common::sys_config::{
    ConnectMetricConfig, DnsMetricConfig, MetricStoreBackend, RuntimeConfigSource,
};
use tokio::sync::mpsc;

#[derive(Default)]
struct TestSourceFactory {
    fail: AtomicBool,
    starts: AtomicUsize,
    current_exit: StdMutex<Option<CancellationToken>>,
    stop_gate: StdMutex<Option<oneshot::Receiver<()>>>,
}

struct TestSource {
    exit: CancellationToken,
    stop_gate: Option<oneshot::Receiver<()>>,
}

#[async_trait::async_trait]
impl MetricSourceHandle for TestSource {
    fn request_stop(&self) {
        self.exit.cancel();
    }
    async fn wait_for_exit(&mut self) {
        self.exit.cancelled().await;
    }
    async fn stop_with_budget(mut self: Box<Self>, _: Duration) -> EventSourceStopOutcome {
        if let Some(gate) = self.stop_gate.take() {
            let _ = gate.await;
        }
        EventSourceStopOutcome::Clean
    }
}

impl MetricSourceFactory for TestSourceFactory {
    fn spawn(&self, _: mpsc::Sender<ConnectMetric>) -> Result<Box<dyn MetricSourceHandle>, String> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            return Err("injected source failure".into());
        }
        let exit = CancellationToken::new();
        *self.current_exit.lock().unwrap() = Some(exit.clone());
        Ok(Box::new(TestSource {
            exit,
            stop_gate: self.stop_gate.lock().unwrap().take(),
        }))
    }
}

fn connect_config(enabled: bool) -> ConnectMetricRuntimeConfig {
    let mut config = ConnectMetricConfig::default().build_runtime();
    config.enabled = enabled;
    config.store.backend = MetricStoreBackend::Memory;
    config
}
fn dns_config(enabled: bool) -> DnsMetricRuntimeConfig {
    let mut config = DnsMetricConfig::default().build_runtime();
    config.enabled = enabled;
    config.store.backend = MetricStoreBackend::Memory;
    config
}
fn event() -> DnsMetricEvent {
    DnsMetricEvent {
        flow_id: 1,
        domain: "example.com".into(),
        query_type: RecordType::A,
        response_code: ResponseCode::NoError,
        status: DnsOutcome::Normal,
        report_time: landscape_common::utils::time::now_ms(),
        duration_ms: 1,
        src_ip: "127.0.0.1".parse().unwrap(),
        answers: vec![],
    }
}

fn service(
    dir: &tempfile::TempDir,
) -> (
    MetricService,
    watch::Sender<ConnectMetricRuntimeConfig>,
    watch::Sender<DnsMetricRuntimeConfig>,
    Arc<TestSourceFactory>,
) {
    let (connect_tx, connect_rx) = watch::channel(connect_config(true));
    let (dns_tx, dns_rx) = watch::channel(dns_config(true));
    let factory = Arc::new(TestSourceFactory::default());
    (
        MetricService::new(
            dir.path().into(),
            connect_rx,
            dns_rx,
            watch::channel(
                landscape_common::sys_config::LandscapeSelfMonitorConfig::default().build_runtime(),
            )
            .1,
            factory.clone(),
        ),
        connect_tx,
        dns_tx,
        factory,
    )
}
async fn wait_until(ready: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(10), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn source_failure_and_unexpected_exit_retry_without_rebuilding_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _connect, _dns, factory) = service(&dir);
    let reporter = service.dns_metric_reporter();
    factory.fail.store(true, Ordering::SeqCst);
    service.start_service().await.unwrap();
    assert_eq!(service.connect.status(), ServiceStatus::Failed);
    assert!(reporter.record_with(event));
    let engine = service.connect.engine();
    factory.fail.store(false, Ordering::SeqCst);
    wait_until(|| service.connect.status() == ServiceStatus::Running).await;
    factory.current_exit.lock().unwrap().as_ref().unwrap().cancel();
    wait_until(|| factory.starts.load(Ordering::SeqCst) == 3).await;
    assert!(Arc::ptr_eq(&engine, &service.connect.engine()));
    assert!(reporter.record_with(event));
    service.stop_service().await.unwrap();
    assert!(!reporter.record_with(|| panic!("stopped reporter")));
}

#[tokio::test(start_paused = true)]
async fn serializes_config_changes_and_uses_latest_after_a_timed_out_stop() {
    let dir = tempfile::tempdir().unwrap();
    let (service, desired, _dns, factory) = service(&dir);
    let reporter = service.dns_metric_reporter();
    let (release, gate) = oneshot::channel();
    *factory.stop_gate.lock().unwrap() = Some(gate);
    service.start_service().await.unwrap();
    assert!(reporter.record_with(event));
    let mut changed = connect_config(true);
    changed.write_batch_size += 1;
    desired.send_replace(changed);
    wait_until(|| service.connect.status() == ServiceStatus::Stopping).await;
    assert!(service.stop_service().await.is_err());
    desired.send_replace(connect_config(false));
    assert!(service.start_service().await.is_err());
    assert_eq!(factory.starts.load(Ordering::SeqCst), 1);
    release.send(()).unwrap();
    service.stop_service().await.unwrap();
    desired.send_replace(connect_config(true));
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(service.connect.status(), ServiceStatus::Stop);
    assert!(!reporter.record_with(|| panic!("stopped reporter")));
    service.start_service().await.unwrap();
    assert!(reporter.record_with(event));
    assert_eq!(factory.starts.load(Ordering::SeqCst), 2);
    desired.send_replace(connect_config(false));
    wait_until(|| service.connect.status() == ServiceStatus::Stop).await;
    assert!(reporter.record_with(event));
    desired.send_replace(connect_config(true));
    wait_until(|| service.connect.status() == ServiceStatus::Running).await;
    assert!(reporter.record_with(event));
    service.stop_service().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_slow_connect_reconfiguration_applies_only_the_latest_config() {
    let dir = tempfile::tempdir().unwrap();
    let (service, desired, _dns, factory) = service(&dir);
    let reporter = service.dns_metric_reporter();
    let (release, gate) = oneshot::channel();
    *factory.stop_gate.lock().unwrap() = Some(gate);
    service.start_service().await.unwrap();
    let mut changed = connect_config(true);
    changed.write_batch_size += 1;
    desired.send_replace(changed.clone());
    wait_until(|| service.connect.status() == ServiceStatus::Stopping).await;
    changed.write_batch_size += 1;
    desired.send_replace(changed);
    tokio::time::advance(STOP_TIMEOUT * 2).await;
    assert_eq!(service.connect.status(), ServiceStatus::Stopping);
    assert!(reporter.record_with(event));
    desired.send_replace(connect_config(false));
    release.send(()).unwrap();
    wait_until(|| service.connect.status() == ServiceStatus::Stop).await;
    assert_eq!(factory.starts.load(Ordering::SeqCst), 1);
    service.stop_service().await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn dns_restarts_without_touching_connect() {
    let dir = tempfile::tempdir().unwrap();
    let (service, _connect, dns, factory) = service(&dir);
    let reporter = service.dns_metric_reporter();
    service.start_service().await.unwrap();
    let connect = service.connect.engine();
    dns.send_replace(dns_config(false));
    wait_until(|| service.dns.status() == ServiceStatus::Stop).await;
    assert!(!reporter.record_with(|| panic!("disabled DNS collected a metric")));
    dns.send_replace(dns_config(true));
    wait_until(|| service.dns.status() == ServiceStatus::Running).await;
    assert!(reporter.record_with(event));
    tokio::time::timeout(Duration::from_secs(2), async {
        while service.get_dns_lightweight_summary(Default::default()).await.total_queries != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(Arc::ptr_eq(&connect, &service.connect.engine()));
    assert_eq!(factory.starts.load(Ordering::SeqCst), 1);
    service.stop_service().await.unwrap();
}

#[tokio::test]
async fn self_monitor_config_and_parent_restart_leave_network_metrics_independent() {
    use landscape_common::sys_config::LandscapeSelfMonitorConfig;
    let dir = tempfile::tempdir().unwrap();
    let (_connect, connect_rx) = watch::channel(connect_config(false));
    let (_dns, dns_rx) = watch::channel(dns_config(false));
    let mut config = LandscapeSelfMonitorConfig {
        enabled: Some(false),
        history_enabled: Some(false),
        ..Default::default()
    }
    .build_runtime();
    let (monitor, monitor_rx) = watch::channel(config.clone());
    let factory = Arc::new(TestSourceFactory::default());
    let service =
        MetricService::new(dir.path().into(), connect_rx, dns_rx, monitor_rx, factory.clone());
    let reporter = service.dns_metric_reporter();
    service.start_service().await.unwrap();
    assert_eq!(service.status(), ServiceStatus::Stop);
    config.enabled = true;
    monitor.send_replace(config);
    let expected =
        if cfg!(feature = "mem-track") { ServiceStatus::Running } else { ServiceStatus::Stop };
    wait_until(|| service.status() == expected).await;
    service.stop_service().await.unwrap();
    assert_eq!(service.status(), ServiceStatus::Stop);
    service.start_service().await.unwrap();
    assert_eq!(service.status(), expected);
    assert_eq!(factory.starts.load(Ordering::SeqCst), 0);
    assert!(!reporter.record_with(|| panic!("disabled DNS collected a metric")));
    service.stop_service().await.unwrap();
}

#[cfg(feature = "metric-persistent")]
#[tokio::test]
async fn committed_dns_config_recovers_after_storage_becomes_available() {
    use crate::sys_service::config_service::LandscapeConfigService;
    use landscape_common::{
        args::WebCommArgs,
        sys_config::{LandscapeConfig, RuntimeConfig},
    };
    use landscape_database::provider::LandscapeDBServiceProvider;
    let dir = tempfile::tempdir().unwrap();
    let file: LandscapeConfig = toml::from_str("[metric]\nmode='memory'").unwrap();
    let runtime = RuntimeConfig::new_with_file_config(
        WebCommArgs {
            config_dir: Some(dir.path().into()),
            database_path: Some("sqlite::memory:".into()),
            ..Default::default()
        },
        Some(file),
    );
    let configs =
        LandscapeConfigService::new(runtime, LandscapeDBServiceProvider::mem_test_db().await).await;
    let service = MetricService::new(
        dir.path().into(),
        configs.subscribe_connect_metric(),
        configs.subscribe_dns_metric(),
        configs.subscribe_self_monitor(),
        Arc::new(TestSourceFactory::default()),
    );
    service.start_service().await.unwrap();
    let reporter = service.dns_metric_reporter();
    let path = dir.path().join(LANDSCAPE_METRIC_DIR_NAME);
    std::fs::write(&path, "").unwrap();
    let (_, hash) = configs.get_dns_metric_from_file().unwrap();
    let requested = DnsMetricConfig { enabled: Some(true), ..Default::default() };
    configs.update_dns_metric_config(requested.clone(), hash).await.unwrap();
    wait_until(|| service.status() == ServiceStatus::Failed).await;
    assert!(!reporter.record_with(|| panic!("DNS unavailable")));
    assert_eq!(service.connect.status(), ServiceStatus::Running);
    assert_eq!(configs.get_dns_metric_from_file().unwrap().0, requested);
    std::fs::remove_file(path).unwrap();
    wait_until(|| service.status() == ServiceStatus::Running).await;
    assert!(reporter.record_with(event));
    service.stop_service().await.unwrap();
}

#[cfg(feature = "metric-persistent")]
#[tokio::test]
async fn dns_backend_switch_preserves_queued_history_across_a_stop_timeout_and_cold_restart() {
    use crate::sys_service::config_service::LandscapeConfigService;
    use landscape_common::{
        LAND_CONFIG, LANDSCAPE_METRIC_DB_VERSION, args::WebCommArgs, sys_config::RuntimeConfig,
    };
    use landscape_database::provider::LandscapeDBServiceProvider;
    use sea_orm::{ConnectionTrait, Database, TransactionTrait};

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(LAND_CONFIG), "[metric]\nmode = 'memory'\n").unwrap();
    let load = || {
        RuntimeConfig::new(WebCommArgs {
            config_dir: Some(dir.path().into()),
            ..Default::default()
        })
    };
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    let factory = Arc::new(TestSourceFactory::default());
    let new_service = |configs: &LandscapeConfigService| {
        MetricService::new(
            dir.path().into(),
            configs.subscribe_connect_metric(),
            configs.subscribe_dns_metric(),
            configs.subscribe_self_monitor(),
            factory.clone(),
        )
    };
    let configs = LandscapeConfigService::new(load(), db.clone()).await;
    let service = new_service(&configs);
    let reporter = service.dns_metric_reporter();
    service.start_service().await.unwrap();
    assert!(reporter.record_with(event));
    tokio::time::timeout(Duration::from_secs(5), async {
        while service.get_dns_lightweight_summary(Default::default()).await.total_queries != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let memory_sender = service.dns.engine().get_dns_msg_channel().unwrap();
    let (mut dns, hash) = configs.get_dns_metric_from_file().unwrap();
    dns.store.backend = Some(MetricStoreBackend::Sqlite);
    configs.update_dns_metric_config(dns, hash).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), memory_sender.closed()).await.unwrap();
    wait_until(|| service.dns.status() == ServiceStatus::Running).await;
    assert_eq!(factory.starts.load(Ordering::SeqCst), 1);
    assert_eq!(service.get_dns_lightweight_summary(Default::default()).await.total_queries, 0);

    let file = dir
        .path()
        .join(LANDSCAPE_METRIC_DIR_NAME)
        .join(format!("metrics_v{LANDSCAPE_METRIC_DB_VERSION}_dns.sqlite"));
    let blocker = Database::connect(format!("sqlite://{}?mode=rw", file.display())).await.unwrap();
    let lock = blocker.begin().await.unwrap();
    // A write transaction holds the SQLite writer lock even when no rows match.
    lock.execute_unprepared("DELETE FROM dns_metrics WHERE 0").await.unwrap();
    for id in 10..16 {
        assert!(reporter.record_with(|| DnsMetricEvent { flow_id: id, ..event() }));
    }
    assert!(service.stop_service().await.is_err());
    assert_eq!(service.dns.status(), ServiceStatus::Stopping);
    assert!(!reporter.record_with(|| panic!("stopping DNS accepted a new event")));
    lock.rollback().await.unwrap();
    service.stop_service().await.unwrap();
    blocker.close().await.unwrap();
    assert_eq!(service.status(), ServiceStatus::Stop);
    drop(service);
    drop(configs);

    let configs = LandscapeConfigService::new(load(), db).await;
    assert_eq!(configs.subscribe_dns_metric().borrow().store.backend, MetricStoreBackend::Sqlite);
    let restarted = new_service(&configs);
    restarted.start_service().await.unwrap();
    let history = restarted.query_dns_history(Default::default()).await;
    let mut ids: Vec<_> = history.items.iter().map(|row| row.flow_id).collect();
    ids.sort_unstable();
    assert_eq!(history.total, 6);
    assert_eq!(ids, [10, 11, 12, 13, 14, 15]);
    assert_eq!(restarted.get_dns_lightweight_summary(Default::default()).await.total_queries, 0);
    restarted.stop_service().await.unwrap();
}
