use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

use hickory_proto::{op::ResponseCode, rr::RecordType};
use landscape_common::metric::{
    connect::ConnectMetric,
    dns::{DnsMetricEvent, DnsOutcome},
};
use landscape_common::sys_config::{LandscapeMetricConfig, RuntimeConfigSource};
use tokio::sync::mpsc;

#[derive(Default)]
struct TestSourceFactory {
    fail_next: AtomicBool,
}

struct TestSource;

#[async_trait::async_trait]
impl MetricSourceHandle for TestSource {
    fn request_stop(&self) {}

    async fn stop_with_budget(self: Box<Self>, _budget: Duration) -> EventSourceStopOutcome {
        EventSourceStopOutcome::Clean
    }
}

impl MetricSourceFactory for TestSourceFactory {
    fn spawn(
        &self,
        _tx: mpsc::Sender<ConnectMetric>,
    ) -> Result<Box<dyn MetricSourceHandle>, String> {
        if self.fail_next.swap(false, Ordering::SeqCst) {
            Err("injected source startup failure".into())
        } else {
            Ok(Box::new(TestSource))
        }
    }
}

fn config(mode: MetricMode) -> MetricRuntimeConfig {
    LandscapeMetricConfig { mode: Some(mode), ..Default::default() }.build_runtime()
}

fn event() -> DnsMetricEvent {
    DnsMetricEvent {
        flow_id: 1,
        domain: "example.com".into(),
        query_type: RecordType::A,
        response_code: ResponseCode::NoError,
        status: DnsOutcome::Normal,
        report_time: 1,
        duration_ms: 1,
        src_ip: "127.0.0.1".parse().unwrap(),
        answers: vec![],
    }
}

async fn service(mode: MetricMode) -> (tempfile::TempDir, MetricService, Arc<TestSourceFactory>) {
    let dir = tempfile::tempdir().unwrap();
    let factory = Arc::new(TestSourceFactory::default());
    let service =
        MetricService::new(dir.path().into(), config(mode), factory.clone()).await.unwrap();
    (dir, service, factory)
}

#[tokio::test]
async fn original_reporter_tracks_engine_replacements_off_and_stop() {
    let (_dir, service, _factory) = service(MetricMode::Memory).await;
    let reporter = service.dns_metric_reporter();
    // DNS may report before the independent eBPF event source is started.
    assert!(reporter.record_with(event));
    service.apply_runtime_config(config(MetricMode::Memory)).await.unwrap();
    assert!(reporter.record_with(event));
    service.apply_runtime_config(config(MetricMode::Off)).await.unwrap();
    assert!(!reporter.record_with(|| panic!("Off must skip event construction")));
    service.apply_runtime_config(config(MetricMode::Memory)).await.unwrap();
    assert!(reporter.record_with(event));
    service.stop_service().await;
    assert!(!reporter.record_with(|| panic!("stopped engine must not receive events")));
}

#[tokio::test]
async fn reporter_created_while_off_observes_later_enable() {
    let (_dir, service, _factory) = service(MetricMode::Off).await;
    let reporter = service.dns_metric_reporter();
    assert!(!reporter.record_with(|| panic!("disabled")));
    service.apply_runtime_config(config(MetricMode::Memory)).await.unwrap();
    assert!(reporter.record_with(event));
    service.stop_service().await;
}

#[tokio::test]
async fn recovery_republishes_through_the_original_reporter() {
    let (_dir, service, _factory) = service(MetricMode::Memory).await;
    let reporter = service.dns_metric_reporter();
    {
        let _guard = service.inner.switch_lock.lock().await;
        service.stop_service_locked().await;
        assert!(!reporter.record_with(|| panic!("recovery gap must skip events")));
        service.restore_previous_engine().await.unwrap();
    }
    assert!(reporter.record_with(event));
    service.stop_service().await;
}

#[tokio::test]
async fn source_failure_and_rollback_do_not_require_notifying_dns() {
    let (_dir, service, factory) = service(MetricMode::Off).await;
    let reporter = service.dns_metric_reporter();
    factory.fail_next.store(true, Ordering::SeqCst);
    assert!(service.apply_runtime_config(config(MetricMode::Memory)).await.is_err());
    // The DNS worker is independent of the eBPF source failure.
    assert!(reporter.record_with(event));
    // Same recovery used by the configuration API, with no DNS update call.
    service.apply_runtime_config(config(MetricMode::Off)).await.unwrap();
    assert!(!reporter.record_with(|| panic!("rolled back to Off")));
    service.stop_service().await;
}
