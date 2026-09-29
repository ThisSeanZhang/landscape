use std::future::Future;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use landscape_common::memtrack::{TaggedFuture, subsystem_from_task_label};
use landscape_common::service::ServiceStatus;
use tokio::sync::Notify;
use tokio::task::JoinHandle as TokioJoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

fn is_exit_status(status: &ServiceStatus) -> bool {
    matches!(status, ServiceStatus::Stopping | ServiceStatus::Stop | ServiceStatus::Failed)
}

/// docker 事件监听的一次运行实例(docker 专属状态结构,仅复用
/// [`ServiceStatus`] 枚举):状态 + 取消信号 + 任务追踪器。
///
/// 每次启动创建新实例,跨 start/stop 周期不复用;进入退出态后 token 永久
/// 取消。全部长驻任务(监听 supervisor / unix 注册 / docker 事件循环)经
/// `spawn_task` 注册进 tracker;停止 = 请求停止 + 确定性等待全部任务结束。
#[derive(Clone)]
pub(super) struct DockerRun {
    inner: Arc<DockerRunInner>,
}

struct DockerRunInner {
    status: RwLock<ServiceStatus>,
    token: CancellationToken,
    tracker: TaskTracker,
    /// 状态变更通知:`start` 侧据此等待运行离开 Staring,避免 REST 端点
    /// 读到中间态。`notify_one` 存储许可,不存在检查/等待间的丢唤醒。
    status_changed: Notify,
}

impl DockerRun {
    pub(super) fn new() -> Self {
        Self {
            inner: Arc::new(DockerRunInner {
                status: RwLock::new(ServiceStatus::Stop),
                token: CancellationToken::new(),
                tracker: TaskTracker::new(),
                status_changed: Notify::new(),
            }),
        }
    }

    /// 锁中毒恢复:临界区内无用户代码,状态值仍可用
    fn read_status(&self) -> RwLockReadGuard<'_, ServiceStatus> {
        self.inner.status.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_status(&self) -> RwLockWriteGuard<'_, ServiceStatus> {
        self.inner.status.write().unwrap_or_else(|e| e.into_inner())
    }

    pub(super) fn current(&self) -> ServiceStatus {
        self.read_status().clone()
    }

    pub(super) fn is_running(&self) -> bool {
        matches!(*self.read_status(), ServiceStatus::Running)
    }

    pub(super) fn is_exit(&self) -> bool {
        is_exit_status(&self.current())
    }

    /// 状态汇报(严格):同状态幂等;非法转换 warn 并拒绝(转换矩阵来自
    /// [`ServiceStatus::can_transition_to`]);进入退出态时取消本实例信号。
    pub(super) fn just_change_status(&self, new_status: ServiceStatus) {
        let mut guard = self.write_status();
        if *guard == new_status {
            // 同态幂等:重复汇报不告警;退出态仍确保取消(对齐 ServiceStatusCell)
            let enters_exit = is_exit_status(&new_status);
            drop(guard);
            if enters_exit {
                self.inner.token.cancel();
            }
            return;
        }
        if !guard.can_transition_to(&new_status) {
            return;
        }
        tracing::debug!("docker service status changed to {new_status:?}");
        let enters_exit = is_exit_status(&new_status);
        *guard = new_status;
        drop(guard);
        if enters_exit {
            self.inner.token.cancel();
        }
        self.inner.status_changed.notify_one();
    }

    /// 等待运行离开 [`ServiceStatus::Staring`](进入 Running 或任一终态)。
    /// 供 `start` 返回前对齐状态,避免 REST 端点读到中间态。
    pub(super) async fn wait_started(&self) {
        loop {
            if !matches!(self.current(), ServiceStatus::Staring) {
                return;
            }
            self.inner.status_changed.notified().await;
        }
    }

    pub(super) fn stop_token(&self) -> CancellationToken {
        self.inner.token.clone()
    }

    /// 追踪式 spawn:任务注册进本实例 tracker,memtrack/tracing 语义与
    /// 全局 `spawn_task` 一致
    pub(super) fn spawn_task<Fut>(
        &self,
        label: &'static str,
        future: Fut,
    ) -> TokioJoinHandle<Fut::Output>
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let tag = subsystem_from_task_label(label);
        self.inner.tracker.spawn(
            TaggedFuture::new(tag, future).instrument(tracing::info_span!("task", task = label)),
        )
    }

    /// 请求停止并确定性等待全部被追踪任务结束;任务未汇报终态则兜底
    /// 置 Failed。返回终态。
    pub(super) async fn wait_stop(&self) -> ServiceStatus {
        {
            let mut guard = self.write_status();
            if matches!(*guard, ServiceStatus::Staring | ServiceStatus::Running) {
                tracing::debug!("current status: {guard:?}, requesting stop");
                *guard = ServiceStatus::Stopping;
            }
        }
        self.inner.status_changed.notify_one();
        self.inner.token.cancel();
        self.inner.tracker.close();
        self.inner.tracker.wait().await;
        let status = self.current();
        if !matches!(status, ServiceStatus::Stop | ServiceStatus::Failed) {
            tracing::warn!(
                status = ?status,
                "docker service stopped without reporting a terminal status; marking as failed"
            );
            self.just_change_status(ServiceStatus::Failed);
            return ServiceStatus::Failed;
        }
        status
    }
}

#[cfg(test)]
mod repro_tests {
    use super::*;

    // 忠实复刻 start_to_listen_event 中 supervisor 的收尾序列:
    // 子任务就绪 -> Running -> 等 stop_token -> 按 failed 标志收敛终态。
    // 注意 wait_stop 必须先于 supervisor 的完成等待调用:它负责 cancel token,
    // 顺序颠倒会死锁(没有任何一方触发取消)。
    #[tokio::test]
    async fn clean_stop_reports_stop() {
        let run = DockerRun::new();
        run.just_change_status(ServiceStatus::Staring);

        let r = run.clone();
        let supervisor = run.spawn_task("test-supervisor", async move {
            let stop_token = r.stop_token();
            if !stop_token.is_cancelled() {
                r.just_change_status(ServiceStatus::Running);
            }
            stop_token.cancelled().await;
            r.just_change_status(ServiceStatus::Stop);
        });

        let status = run.wait_stop().await;
        let _ = supervisor.await;
        assert_eq!(status, ServiceStatus::Stop, "clean stop should converge to Stop");
    }
}
