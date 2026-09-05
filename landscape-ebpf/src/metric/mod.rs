use std::os::fd::{FromRawFd, OwnedFd};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use landscape_common::concurrency::{spawn_task, task_label};
use landscape_common::event::ConnectMessage;
use landscape_common::metric::connect::ConnectMetric;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;

use crate::maps::LandscapeMapPath;

/// 事件源实际终止方式,决定服务最终状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventSourceStopOutcome {
    /// join 返回 Ok(()),正常退出
    #[default]
    Clean,
    /// join 返回 Err,事件源任务内部 panic
    Panicked,
    /// 预算内未退出,已 abort 强杀
    Aborted,
}

/// 事件源句柄的行为抽象:生产端为 ebpf ringbuf,测试端注入 mock。
#[async_trait]
pub trait MetricSourceHandle: Send + Sync {
    /// 触发取消信号,让后台任务尽快退出(只发信号,不等待回收)。
    fn request_stop(&self);
    /// 限时回收:正常退出/panic/超时 abort,返回实际终止方式。消费句柄。
    async fn stop_with_budget(self: Box<Self>, budget: Duration) -> EventSourceStopOutcome;
}

pub trait MetricSourceFactory: Send + Sync {
    fn spawn(
        &self,
        connect_msg_tx: mpsc::Sender<ConnectMessage>,
    ) -> Result<Box<dyn MetricSourceHandle>, String>;
}

pub struct EbpfMetricSourceFactory {
    paths: Arc<LandscapeMapPath>,
}

impl EbpfMetricSourceFactory {
    pub fn new(paths: Arc<LandscapeMapPath>) -> Self {
        Self { paths }
    }
}

impl MetricSourceFactory for EbpfMetricSourceFactory {
    fn spawn(
        &self,
        connect_msg_tx: mpsc::Sender<ConnectMessage>,
    ) -> Result<Box<dyn MetricSourceHandle>, String> {
        Ok(Box::new(ConnectMetricEventSource::spawn(self.paths.clone(), connect_msg_tx)?))
    }
}

pub(crate) fn build_connect_ringbuf(
    map: &dyn libbpf_rs::MapCore,
    tx_slot: Arc<ArcSwapOption<mpsc::Sender<ConnectMessage>>>,
) -> Result<libbpf_rs::RingBuffer<'static>, String> {
    let nat_metric_callback = move |data: &[u8]| -> i32 {
        let event = match ConnectMetric::try_from(data) {
            Ok(ev) => ev,
            Err(err) => {
                tracing::warn!(
                    len = data.len(),
                    expected = std::mem::size_of::<ConnectMetric>(),
                    error = %err,
                    "dropping nat_conn_metric_event with unexpected wire size"
                );
                return 0;
            }
        };
        if let Some(tx) = tx_slot.load().as_ref() {
            let _ = tx.try_send(ConnectMessage::Metric(event));
        }
        0
    };

    let mut builder = libbpf_rs::RingBufferBuilder::new();
    builder
        // .add(&firewall_conn_metric_events, firewall_metric_callback)
        // .expect("failed to add firewall_conn_metric_events ringbuf")
        .add(map, nat_metric_callback)
        .map_err(|error| format!("failed to add nat_metric_events ringbuf: {error}"))?;
    builder.build().map_err(|error| format!("failed to build ringbuf: {error}"))
}

pub(crate) fn dup_epoll_async_fd(epoll_fd: i32) -> Result<AsyncFd<OwnedFd>, String> {
    let dup_fd = unsafe { libc::dup(epoll_fd) };
    if dup_fd < 0 {
        return Err(format!("failed to dup ringbuf epoll fd: {}", std::io::Error::last_os_error()));
    }
    AsyncFd::new(unsafe { OwnedFd::from_raw_fd(dup_fd) })
        .map_err(|error| format!("failed to create AsyncFd for ringbuf epoll fd: {error}"))
}

pub struct ConnectMetricEventSource {
    cancel: CancellationToken,
    handle: JoinHandle<()>,
    tx_slot: Arc<ArcSwapOption<mpsc::Sender<ConnectMessage>>>,
}

impl ConnectMetricEventSource {
    pub fn spawn(
        paths: Arc<LandscapeMapPath>,
        connect_msg_tx: mpsc::Sender<ConnectMessage>,
    ) -> Result<Self, String> {
        let tx_slot = Arc::new(ArcSwapOption::new(Some(Arc::new(connect_msg_tx))));
        let nat_metric_events = libbpf_rs::MapHandle::from_pinned_path(&paths.nat_metric_events)
            .map_err(|error| format!("failed to open pinned nat_metric_events map: {error}"))?;
        let ringbuf = build_connect_ringbuf(&nat_metric_events, tx_slot.clone())?;
        let async_fd = dup_epoll_async_fd(ringbuf.epoll_fd())?;
        let cancel = CancellationToken::new();
        let handle = spawn_task(
            task_label::task::METRIC_EBPF_CONNECT_EVENT_SOURCE,
            run_ringbuf_loop(ringbuf, async_fd, cancel.clone()),
        );
        Ok(ConnectMetricEventSource { cancel, handle, tx_slot })
    }

    /// 替换事件流向的 channel(后续事件走新 channel)。备用演进路径:
    /// 将来引擎切换只换 tx 而不重启事件源时使用。
    pub fn attach_channel(&self, connect_msg_tx: mpsc::Sender<ConnectMessage>) {
        self.tx_slot.store(Some(Arc::new(connect_msg_tx)));
    }

    #[cfg(test)]
    pub(crate) fn test_new(
        cancel: CancellationToken,
        handle: JoinHandle<()>,
        tx_slot: Arc<ArcSwapOption<mpsc::Sender<ConnectMessage>>>,
    ) -> Self {
        ConnectMetricEventSource { cancel, handle, tx_slot }
    }
}

impl Drop for ConnectMetricEventSource {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

#[async_trait]
impl MetricSourceHandle for ConnectMetricEventSource {
    fn request_stop(&self) {
        self.cancel.cancel();
    }

    async fn stop_with_budget(mut self: Box<Self>, budget: Duration) -> EventSourceStopOutcome {
        self.cancel.cancel();
        match timeout(budget, &mut self.handle).await {
            Ok(Ok(())) => EventSourceStopOutcome::Clean,
            Ok(Err(_)) => {
                tracing::error!("metric event source task exited with an uncaught panic");
                EventSourceStopOutcome::Panicked
            }
            Err(_) => {
                tracing::error!(
                    "timed out waiting for metric event source to exit; aborting the stuck task"
                );
                self.handle.abort();
                let _ = (&mut self.handle).await;
                EventSourceStopOutcome::Aborted
            }
        }
    }
}

pub async fn run_ringbuf_loop(
    ringbuf: libbpf_rs::RingBuffer<'_>,
    async_fd: AsyncFd<OwnedFd>,
    cancel: CancellationToken,
) {
    let mut async_fd = async_fd;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("ringbuf consumer loop exited on cancellation");
                return;
            }
            readable = async_fd.readable() => {
                match readable {
                    Ok(mut guard) => {
                        guard.clear_ready();
                        if let Err(error) = ringbuf.consume() {
                            tracing::error!("failed to consume ringbuf events: {}", error);
                        }
                    }
                    Err(error) => {
                        tracing::error!("ringbuf epoll fd invalid ({error}); re-creating AsyncFd");
                        match dup_epoll_async_fd(ringbuf.epoll_fd()) {
                            Ok(fresh) => async_fd = fresh,
                            Err(e) => {
                                tracing::error!("failed to re-create ringbuf AsyncFd: {e}; retrying");
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
            }
        }
    }
}
