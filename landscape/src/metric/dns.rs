use super::supervisor::{
    MetricComponent, Pipeline, drain, first_attempt_complete, wait_for_change,
};
use landscape_common::metric::dns::DnsMetricReporter;
use landscape_common::{service::ServiceStatus, sys_config::DnsMetricRuntimeConfig};
use landscape_metric::DnsMetricEngine;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

pub(super) struct DnsMetricService {
    path: PathBuf,
    pipeline: Pipeline<DnsMetricRuntimeConfig, DnsMetricEngine>,
    pub(super) reporter: DnsMetricReporter,
}

impl DnsMetricService {
    pub(super) fn new(path: PathBuf, desired: watch::Receiver<DnsMetricRuntimeConfig>) -> Self {
        Self {
            path,
            pipeline: Pipeline::new(desired, DnsMetricEngine::off()),
            reporter: DnsMetricReporter::default(),
        }
    }
}

#[async_trait::async_trait]
impl MetricComponent for DnsMetricService {
    type Config = DnsMetricRuntimeConfig;
    type Engine = DnsMetricEngine;

    fn pipeline(&self) -> &Pipeline<Self::Config, Self::Engine> {
        &self.pipeline
    }

    fn enabled(config: &Self::Config) -> bool {
        config.enabled
    }
    async fn serve(
        &self,
        config: &Self::Config,
        rx: &mut watch::Receiver<Self::Config>,
        stop: &CancellationToken,
        ready: &mut Option<oneshot::Sender<()>>,
    ) -> Result<(), String> {
        self.pipeline.status.set(ServiceStatus::Staring);
        let engine = Arc::new(DnsMetricEngine::new(self.path.clone(), config.clone()).await?);
        if stop.is_cancelled() || *rx.borrow() != *config || rx.has_changed().is_err() {
            self.pipeline.status.set(ServiceStatus::Stopping);
            drain(engine.shutdown()).await;
            return Ok(());
        }
        let tx = engine.get_dns_msg_channel().expect("active DNS engine");
        self.pipeline.engine.store(engine.clone());
        self.reporter.replace_sender(Some(tx.clone()));
        self.pipeline.status.set(ServiceStatus::Running);
        first_attempt_complete(ready);
        let result = tokio::select! {
            _ = wait_for_change(rx, config, stop) => Ok(()),
            _ = tx.closed() => Err("DNS metric worker exited".into()),
        };
        self.pipeline.status.set(ServiceStatus::Stopping);
        self.reporter.replace_sender(None);
        self.pipeline.engine.store(self.pipeline.off.clone());
        drain(engine.shutdown()).await;
        result
    }
}
