use std::{future::Future, sync::Arc};

use arc_swap::ArcSwap;
use landscape_common::service::ServiceStatus;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

use super::{INITIAL_RETRY, MAX_RETRY, STOP_TIMEOUT, state::MetricStatus};

pub(super) struct Pipeline<C, E> {
    desired: watch::Receiver<C>,
    pub(super) engine: ArcSwap<E>,
    pub(super) off: Arc<E>,
    pub(super) status: MetricStatus,
}
impl<C, E> Pipeline<C, E> {
    pub(super) fn new(desired: watch::Receiver<C>, off: E) -> Self {
        let off = Arc::new(off);
        Self {
            desired,
            engine: ArcSwap::from(off.clone()),
            off,
            status: MetricStatus::default(),
        }
    }
}

pub(super) async fn wait_for_change<C: PartialEq>(
    desired: &mut watch::Receiver<C>,
    current: &C,
    stop: &CancellationToken,
) {
    tokio::select! {
        _ = stop.cancelled() => {},
        _ = desired.wait_for(|value| value != current) => {},
    }
}

pub(super) fn first_attempt_complete(ready: &mut Option<oneshot::Sender<()>>) {
    if let Some(ready) = ready.take() {
        let _ = ready.send(());
    }
}

#[async_trait::async_trait]
pub(super) trait MetricComponent: Sync {
    type Config: Clone + PartialEq + Send + Sync;
    type Engine: Send + Sync;

    fn pipeline(&self) -> &Pipeline<Self::Config, Self::Engine>;
    fn enabled(config: &Self::Config) -> bool;

    fn engine(&self) -> Arc<Self::Engine> {
        self.pipeline().engine.load_full()
    }

    fn status(&self) -> ServiceStatus {
        self.pipeline().status.current()
    }

    async fn serve(
        &self,
        config: &Self::Config,
        desired: &mut watch::Receiver<Self::Config>,
        stop: &CancellationToken,
        ready: &mut Option<oneshot::Sender<()>>,
    ) -> Result<(), String>;

    async fn supervise(&self, stop: &CancellationToken, ready: oneshot::Sender<()>) {
        let pipeline = self.pipeline();
        let mut desired = pipeline.desired.clone();
        let mut ready = Some(ready);
        let mut delay = INITIAL_RETRY;
        while !stop.is_cancelled() && desired.has_changed().is_ok() {
            let config = desired.borrow_and_update().clone();
            if !Self::enabled(&config) {
                pipeline.status.set(ServiceStatus::Stop);
                first_attempt_complete(&mut ready);
                wait_for_change(&mut desired, &config, stop).await;
                delay = INITIAL_RETRY;
                continue;
            }
            let result = self.serve(&config, &mut desired, stop, &mut ready).await;
            if let Err(error) = result {
                pipeline.status.set(ServiceStatus::Failed);
                tracing::warn!(%error, "metric engine failed; retrying committed configuration");
                first_attempt_complete(&mut ready);
                tokio::select! {
                    _ = wait_for_change(&mut desired, &config, stop) => delay = INITIAL_RETRY,
                    _ = tokio::time::sleep(delay) => delay = (delay * 2).min(MAX_RETRY),
                }
            } else {
                delay = INITIAL_RETRY;
            }
        }
        pipeline.status.set(ServiceStatus::Stop);
    }
}

pub(super) async fn drain(work: impl Future<Output = ()>) {
    tokio::pin!(work);
    if tokio::time::timeout(STOP_TIMEOUT, &mut work).await.is_err() {
        tracing::warn!("metric workers are still draining");
        work.await;
    }
}
