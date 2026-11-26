use super::supervisor::{
    MetricComponent, Pipeline, drain, first_attempt_complete, wait_for_change,
};
use super::{INITIAL_RETRY, MAX_RETRY};
use landscape_common::metric::connect::ConnectMetric;
use landscape_common::{service::ServiceStatus, sys_config::ConnectMetricRuntimeConfig};
use landscape_ebpf::metric::{EventSourceStopOutcome, MetricSourceFactory};
use landscape_metric::ConnectMetricEngine;
use std::{future::Future, time::Duration};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::mpsc;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

pub(super) struct ConnectMetricService {
    path: PathBuf,
    pipeline: Pipeline<ConnectMetricRuntimeConfig, ConnectMetricEngine>,
    source_factory: Arc<dyn MetricSourceFactory>,
}

impl ConnectMetricService {
    pub(super) fn new(
        path: PathBuf,
        desired: watch::Receiver<ConnectMetricRuntimeConfig>,
        source_factory: Arc<dyn MetricSourceFactory>,
    ) -> Self {
        Self {
            path,
            pipeline: Pipeline::new(desired, ConnectMetricEngine::off()),
            source_factory,
        }
    }
}

#[async_trait::async_trait]
impl MetricComponent for ConnectMetricService {
    type Config = ConnectMetricRuntimeConfig;
    type Engine = ConnectMetricEngine;

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
        let engine = Arc::new(ConnectMetricEngine::new(self.path.clone(), config.clone()).await?);
        if stop.is_cancelled() || *rx.borrow() != *config || rx.has_changed().is_err() {
            self.pipeline.status.set(ServiceStatus::Stopping);
            drain(engine.shutdown()).await;
            return Ok(());
        }
        let tx = engine.get_connect_msg_channel().expect("active connect engine");
        self.pipeline.engine.store(engine.clone());
        let until_end = async {
            tokio::select! {
                _ = wait_for_change(rx, config, stop) => Ok(()),
                _ = tx.closed() => Err("connect worker exited".into()),
            }
        };
        let result = self.collect(&tx, until_end, ready).await;
        self.pipeline.status.set(ServiceStatus::Stopping);
        self.pipeline.engine.store(self.pipeline.off.clone());
        drain(engine.shutdown()).await;
        result
    }
}

impl ConnectMetricService {
    /// The eBPF source can recover independently of the DNS reporter and storage workers.
    async fn collect(
        &self,
        connect: &mpsc::Sender<ConnectMetric>,
        until_end: impl Future<Output = Result<(), String>>,
        ready: &mut Option<oneshot::Sender<()>>,
    ) -> Result<(), String> {
        tokio::pin!(until_end);
        let mut delay = INITIAL_RETRY;
        loop {
            self.pipeline.status.set(ServiceStatus::Staring);
            match self.source_factory.spawn(connect.clone()) {
                Ok(mut source) => {
                    self.pipeline.status.set(ServiceStatus::Running);
                    first_attempt_complete(ready);
                    tokio::select! {
                        biased;
                        result = &mut until_end => {
                            self.pipeline.status.set(ServiceStatus::Stopping);
                            let outcome = source.stop_with_budget(Duration::from_secs(3)).await;
                            if outcome != EventSourceStopOutcome::Clean {
                                tracing::warn!(?outcome, "metric source stopped");
                            }
                            return result;
                        }
                        _ = source.wait_for_exit() => tracing::warn!("metric source exited unexpectedly"),
                    }
                }
                Err(error) => tracing::warn!(%error, "failed to start metric source"),
            }
            self.pipeline.status.set(ServiceStatus::Failed);
            first_attempt_complete(ready);
            tokio::select! {
                biased;
                result = &mut until_end => return result,
                _ = tokio::time::sleep(delay) => delay = (delay * 2).min(MAX_RETRY),
            }
        }
    }
}
