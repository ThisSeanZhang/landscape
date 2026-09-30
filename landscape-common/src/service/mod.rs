use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use serde::Serialize;
use tokio::task::JoinHandle as TokioJoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::Instrument;

use landscape_macro::LdApiError;

pub mod controller;
pub mod manager;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum ServiceConfigError {
    #[error("{service_name} service config not found")]
    #[api_error(id = "service.config_not_found", status = 404)]
    NotFound { service_name: &'static str },

    #[error(
        "Service '{service_name}' cannot be configured on interface '{iface_name}': zone mismatch"
    )]
    #[api_error(id = "service.zone_mismatch", status = 422)]
    ZoneMismatch { service_name: crate::config_service::iface::ServiceKind, iface_name: String },

    #[error("Interface '{iface_name}' not found")]
    #[api_error(id = "service.iface_not_found", status = 404)]
    IfaceNotFound { iface_name: String },

    #[error("Invalid service config: {reason}")]
    #[api_error(id = "service.invalid_config", status = 422)]
    InvalidConfig { reason: String },
}

#[derive(Serialize, Debug, PartialEq, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    // 启动中
    Staring,
    // 正在运行
    Running,
    // 正在停止
    Stopping,
    // 停止运行
    #[default]
    Stop,
    // 设计上未运行(禁用配置显式汇报)
    Disabled,
    // 异常停止
    Failed,
}

impl ServiceStatus {
    // 检查当前状态是否可以转换到目标状态
    pub fn can_transition_to(&self, target: &ServiceStatus) -> bool {
        let can = matches!(
            (self, target),
            (ServiceStatus::Stop, ServiceStatus::Staring)
                | (ServiceStatus::Stop, ServiceStatus::Disabled)
                | (ServiceStatus::Failed, ServiceStatus::Staring)
                | (ServiceStatus::Staring, ServiceStatus::Running)
                | (ServiceStatus::Staring, ServiceStatus::Stopping)
                | (ServiceStatus::Staring, ServiceStatus::Stop)
                | (ServiceStatus::Staring, ServiceStatus::Failed)
                | (ServiceStatus::Running, ServiceStatus::Stopping)
                | (ServiceStatus::Running, ServiceStatus::Stop)
                | (ServiceStatus::Running, ServiceStatus::Failed)
                | (ServiceStatus::Stopping, ServiceStatus::Stop)
                | (ServiceStatus::Stopping, ServiceStatus::Failed)
                | (ServiceStatus::Failed, ServiceStatus::Stop)
        );
        if !can {
            tracing::warn!("invalid status transition: {self:?} -> {target:?}");
        }
        can
    }

    /// 是否为退出态:进入这些状态后服务不可继续运行,关联取消信号必须触发
    fn is_exit_state(&self) -> bool {
        matches!(
            self,
            ServiceStatus::Stopping
                | ServiceStatus::Stop
                | ServiceStatus::Disabled
                | ServiceStatus::Failed
        )
    }
}

/// 一次启动尝试的观测结果。
///
/// controller 层据此实现"验证后落库"(Running 才持久化)或"落库后验证"
/// (非 Running 触发双回滚);Timeout 的策略语义(放行或中止)由调用方
/// 按服务域决定,本类型不做判断。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartOutcome {
    /// 启动成功,当前处于 Running
    Running,
    /// 启动失败(含启动过程panic/静默死亡,由死亡监视兜底)
    Failed,
    /// 启动尝试以 Stop 结束(未经历 Running,或启动过程中被请求停止)
    Stopped,
    /// 干净停止:starter 显式汇报 [`ServiceStatus::Disabled`](禁用配置),
    /// 设计上就不运行。与 [`StartOutcome::Stopped`](真实经历过一次运行后停止)区分。
    CleanStop,
    /// 超时仍未离开 Staring/Stopping
    Timeout,
    /// 配置未投递(通道满被去重或服务任务已退出):不会有运行被触发。
    /// 与 [`StartOutcome::Stopped`](真实经历过一次运行后停止)区分;
    /// 回滚接线按"请求被拒绝"处理,不进入 DB 补偿范围。
    NotDelivered,
}

/// 轮询等待的采样间隔:仅测试与低频观测使用,10ms 对测试延迟无感知
pub(crate) const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// 服务生命周期状态单元:状态机 + 关联取消信号(不可分离)。
///
/// 不变量:所有状态写入都收敛在本类型的方法内;进入退出态
/// (Stopping/Stop/Failed)时自动 cancel 关联的 [`CancellationToken`],
/// 任何写入路径(服务自报/停止请求/死亡兜底)都无法绕过该副作用。
struct ServiceStatusCell {
    status: RwLock<ServiceStatus>,
    stop: CancellationToken,
}

impl ServiceStatusCell {
    fn new() -> Self {
        Self {
            status: RwLock::new(ServiceStatus::default()),
            stop: CancellationToken::new(),
        }
    }

    /// 锁中毒恢复:临界区内无用户代码,中毒只意味着写入侧 panic,状态值仍可用
    fn read(&self) -> RwLockReadGuard<'_, ServiceStatus> {
        self.status.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, ServiceStatus> {
        self.status.write().unwrap_or_else(|e| e.into_inner())
    }

    fn current(&self) -> ServiceStatus {
        self.read().clone()
    }

    fn is_running(&self) -> bool {
        matches!(*self.read(), ServiceStatus::Running)
    }

    fn is_stop(&self) -> bool {
        matches!(
            *self.read(),
            ServiceStatus::Stop | ServiceStatus::Disabled | ServiceStatus::Failed
        )
    }

    fn is_active(&self) -> bool {
        matches!(*self.read(), ServiceStatus::Staring | ServiceStatus::Running)
    }

    fn is_exit(&self) -> bool {
        self.read().is_exit_state()
    }

    fn stop_token(&self) -> CancellationToken {
        self.stop.clone()
    }

    /// 状态汇报(严格):同状态视为幂等 no-op;非法转换 warn 并拒绝,保留状态机防呆
    fn just_change_status(&self, new_status: ServiceStatus) {
        let mut guard = self.write();
        if *guard == new_status {
            // 同态幂等:重复汇报不告警;退出态仍需确保取消。
            let enters_exit_state = new_status.is_exit_state();
            drop(guard);
            if enters_exit_state {
                self.stop.cancel();
            }
            return;
        }
        if guard.can_transition_to(&new_status) {
            tracing::debug!("status changed to {new_status:?}");
            let enters_exit_state = new_status.is_exit_state();
            *guard = new_status;
            drop(guard);
            if enters_exit_state {
                self.stop.cancel();
            }
        }
    }

    /// 停止请求(宽松幂等):active → Staring/Running 置 Stopping;已在退出态则不动。
    /// 对应 systemd 的 job(转换请求)语义,与 [`ServiceStatusCell::just_change_status`]
    /// 的 state(观测状态)语义相对。
    fn request_stop(&self) {
        let mut guard = self.write();
        if matches!(*guard, ServiceStatus::Staring | ServiceStatus::Running) {
            tracing::debug!("current status: {guard:?}, requesting stop");
            *guard = ServiceStatus::Stopping;
        }
        drop(guard);
        // 幂等:无论是否发生写入都确保取消信号与状态一致
        self.stop.cancel();
    }
}

/// 被观测的服务:一次服务运行实例的句柄。
///
/// 结构:状态单元(展示:快照读;协调:退出即取消)+ 任务追踪器
/// (协调:确定性等待全部任务结束)。每次重启创建新实例,token/tracker
/// 与实例同生命周期,实例间完全隔离。
///
/// 对外等待语义:
/// - `stop_token()`:服务循环/子任务监听停止信号(`token.cancelled()`)
/// - `wait_stop()`:请求停止并确定性等待全部被追踪任务结束;
///   结束后状态未到终态则兜底置 Failed(systemd 判活语义)
///
/// 使用边界:本类型(及 `WatchService` 别名)仅适用于"一次运行 = 一棵
/// tokio 任务树"的服务,即经 [`super::manager::ServiceManager`] 管理的
/// 配置驱动服务。单例服务不在本层持有状态,各自拥有专属状态结构,
/// 仅复用 [`ServiceStatus`] 枚举与转换矩阵:
/// - docker:`DockerRun`(landscape/src/docker/run.rs,状态+token+tracker,per-run)
/// - dns:无状态持有者,由 per-flow 运行时投影(landscape-dns/src/server.rs)
/// - gateway:`GatewayRun`(landscape-gateway/src/lib.rs,专用线程 per-run)
/// - metric:`MetricStatus`(landscape/src/metric/state.rs,纯展示状态)
#[derive(Clone)]
pub struct ServiceHandle {
    inner: Arc<HandleInner>,
}

struct HandleInner {
    cell: ServiceStatusCell,
    tracker: TaskTracker,
}

impl Debug for ServiceHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceHandle").field("status", &self.current()).finish()
    }
}

impl Default for ServiceHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceHandle {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HandleInner {
                cell: ServiceStatusCell::new(),
                tracker: TaskTracker::new(),
            }),
        }
    }

    /// 两个句柄是否指向同一个服务运行实例
    pub fn ptr_eq(left: &ServiceHandle, right: &ServiceHandle) -> bool {
        Arc::ptr_eq(&left.inner, &right.inner)
    }

    pub fn current(&self) -> ServiceStatus {
        self.inner.cell.current()
    }

    pub fn is_exit(&self) -> bool {
        self.inner.cell.is_exit()
    }

    pub fn is_running(&self) -> bool {
        self.inner.cell.is_running()
    }

    pub fn is_stop(&self) -> bool {
        self.inner.cell.is_stop()
    }

    pub fn is_active(&self) -> bool {
        self.inner.cell.is_active()
    }

    /// 状态汇报(严格校验):保留原有状态机防呆语义,40+ 调用点签名不变
    pub fn just_change_status(&self, new_status: ServiceStatus) {
        self.inner.cell.just_change_status(new_status);
    }

    /// 停止信号:服务循环/停止桥任务/子任务统一监听 `token.cancelled()`。
    /// 进入退出态(Stopping/Stop/Failed)时触发,幂等。
    pub fn stop_token(&self) -> CancellationToken {
        self.inner.cell.stop_token()
    }

    /// 追踪式 spawn:任务注册进本实例的 tracker,memtrack/tracing 语义与
    /// [`crate::concurrency::spawn_task`] 一致。服务实例的长驻任务必须经
    /// 此入口 spawn,否则 `wait_stop` 无法等待其结束。
    pub fn spawn_task<Fut>(&self, label: &'static str, future: Fut) -> TokioJoinHandle<Fut::Output>
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let tag = crate::memtrack::subsystem_from_task_label(label);
        self.inner.tracker.spawn(
            crate::memtrack::TaggedFuture::new(tag, future)
                .instrument(tracing::info_span!("task", task = label)),
        )
    }

    /// [`ServiceHandle::spawn_task`] 的带资源标签变体,与
    /// [`crate::concurrency::spawn_task_with_resource`] 对齐
    pub fn spawn_task_with_resource<Fut>(
        &self,
        label: &'static str,
        resource: impl std::fmt::Display,
        future: Fut,
    ) -> TokioJoinHandle<Fut::Output>
    where
        Fut: Future + Send + 'static,
        Fut::Output: Send + 'static,
    {
        let resource = resource.to_string();
        let tag = crate::memtrack::subsystem_from_task_label(label);
        self.inner.tracker.spawn(
            crate::memtrack::TaggedFuture::new(tag, future)
                .instrument(tracing::info_span!("task", task = label, resource = %resource)),
        )
    }

    /// 关闭 tracker 并挂死亡监视(OTP monitor 语义):全部被追踪任务退出后,
    /// 若状态仍停留在 Staring/Running,判定为静默死亡,置 Failed 并取消信号。
    /// 由 ServiceManager 在 `start()` 返回后调用;close 不阻止后续 spawn,
    /// 运行期新 spawn 的任务仍被追踪。
    pub(crate) fn supervise_lifecycle(&self) {
        self.inner.tracker.close();
        let handle = self.clone();
        crate::concurrency::spawn_task(
            crate::concurrency::task_label::task::SERVICE_DEATH_WATCH,
            async move {
                handle.inner.tracker.wait().await;
                let status = handle.current();
                if matches!(status, ServiceStatus::Staring | ServiceStatus::Running) {
                    tracing::warn!(
                        status = ?status,
                        "service tasks all exited without a terminal status; marking as failed"
                    );
                    handle.just_change_status(ServiceStatus::Failed);
                }
            },
        );
    }

    /// 请求停止并确定性等待全部被追踪任务结束(替代旧的"发 Stopping 等自报 Stop"):
    /// 不再依赖服务诚实汇报;等待结束后状态未到终态则兜底置 Failed。
    pub async fn wait_stop(&self) {
        self.inner.cell.request_stop();
        self.inner.tracker.close();
        self.inner.tracker.wait().await;
        let status = self.current();
        if !self.inner.cell.is_stop() {
            tracing::warn!(
                status = ?status,
                "service stopped without reporting a terminal status; marking as failed"
            );
            self.inner.cell.just_change_status(ServiceStatus::Failed);
        }
    }

    /// 轮询等待状态满足谓词(测试辅助原语):谓词先查后睡,无丢失唤醒问题。
    /// 生产代码应使用 `stop_token()` / `wait_start_outcome()` 的事件语义。
    pub async fn wait_for(&self, pred: impl Fn(&ServiceStatus) -> bool) {
        while !pred(&self.current()) {
            tokio::time::sleep(STATUS_POLL_INTERVAL).await;
        }
    }

    /// 观测一次启动尝试的结果:以首次到达的终态为准(Running 期间快速翻转到
    /// Failed 的按 Failed 处理,对回滚语义是正确的);显式汇报的 `Disabled`
    /// 观测为 [`StartOutcome::CleanStop`](禁用语义);Staring/Stopping 期间
    /// 持续等待,超时返回 [`StartOutcome::Timeout`]。
    pub async fn wait_start_outcome(&self, timeout: Duration) -> StartOutcome {
        let observe = async {
            loop {
                match self.current() {
                    ServiceStatus::Running => return StartOutcome::Running,
                    ServiceStatus::Disabled => return StartOutcome::CleanStop,
                    ServiceStatus::Stop => return StartOutcome::Stopped,
                    ServiceStatus::Failed => return StartOutcome::Failed,
                    // 启动进行中/正在收尾:等待其到达终态
                    ServiceStatus::Staring | ServiceStatus::Stopping => {}
                }
                tokio::time::sleep(STATUS_POLL_INTERVAL).await;
            }
        };
        tokio::time::timeout(timeout, observe).await.unwrap_or(StartOutcome::Timeout)
    }
}

impl Serialize for ServiceHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.current().serialize(serializer)
    }
}

/// 兼容别名:既有 40+ 调用点零改动;公共面为 [`ServiceHandle`] 的全量转发
pub type WatchService = ServiceHandle;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn handle_at(status: ServiceStatus) -> ServiceHandle {
        let handle = ServiceHandle::new();
        handle.just_change_status(ServiceStatus::Staring);
        handle.just_change_status(status);
        handle
    }

    #[test]
    fn transition_matrix_preserved() {
        // 合法转换抽查(完整矩阵由后续用例覆盖)
        assert!(ServiceStatus::Stop.can_transition_to(&ServiceStatus::Staring));
        assert!(ServiceStatus::Staring.can_transition_to(&ServiceStatus::Running));
        assert!(ServiceStatus::Running.can_transition_to(&ServiceStatus::Stopping));
        assert!(ServiceStatus::Stopping.can_transition_to(&ServiceStatus::Stop));
        assert!(ServiceStatus::Failed.can_transition_to(&ServiceStatus::Staring));
        // 非法转换
        assert!(!ServiceStatus::Stop.can_transition_to(&ServiceStatus::Running));
        assert!(!ServiceStatus::Running.can_transition_to(&ServiceStatus::Staring));
        assert!(!ServiceStatus::Stopping.can_transition_to(&ServiceStatus::Running));
        assert!(!ServiceStatus::Stop.can_transition_to(&ServiceStatus::Failed));
    }

    #[tokio::test]
    async fn same_state_report_is_noop() {
        // start 预置 + 任务内重复置 Staring:须静默接受且不影响 token
        let handle = handle_at(ServiceStatus::Staring);
        let token = handle.stop_token();
        handle.just_change_status(ServiceStatus::Staring);
        assert_eq!(handle.current(), ServiceStatus::Staring);
        assert!(!token.is_cancelled());
        // 退出态重复汇报仍须保证取消信号已触发
        let handle = handle_at(ServiceStatus::Running);
        handle.just_change_status(ServiceStatus::Stop);
        handle.just_change_status(ServiceStatus::Stop);
        assert_eq!(handle.current(), ServiceStatus::Stop);
        assert!(handle.stop_token().is_cancelled());
    }

    #[tokio::test]
    async fn exit_transition_cancels_token() {
        for target in [ServiceStatus::Stopping, ServiceStatus::Stop, ServiceStatus::Failed] {
            let handle = handle_at(ServiceStatus::Running);
            let token = handle.stop_token();
            assert!(!token.is_cancelled());
            handle.just_change_status(target.clone());
            assert!(token.is_cancelled(), "token must cancel on -> {target:?}");
            assert_eq!(handle.current(), target);
        }
        // Staring 起点的退出转换
        for target in [ServiceStatus::Stopping, ServiceStatus::Stop, ServiceStatus::Failed] {
            let handle = handle_at(ServiceStatus::Staring);
            handle.just_change_status(target.clone());
            assert!(
                handle.stop_token().is_cancelled(),
                "token must cancel on Staring -> {target:?}"
            );
        }
    }

    #[tokio::test]
    async fn non_exit_transition_keeps_token_alive() {
        let handle = ServiceHandle::new();
        handle.just_change_status(ServiceStatus::Staring);
        assert!(!handle.stop_token().is_cancelled());
        handle.just_change_status(ServiceStatus::Running);
        assert!(!handle.stop_token().is_cancelled());
    }

    #[test]
    fn illegal_transition_rejected_and_keeps_status() {
        let handle = handle_at(ServiceStatus::Running);
        // Stop -> Running 非法:状态保持 Running,token 不受影响
        handle.just_change_status(ServiceStatus::Staring);
        assert_eq!(handle.current(), ServiceStatus::Running);
        assert!(!handle.stop_token().is_cancelled());
    }

    #[tokio::test]
    async fn request_stop_is_idempotent() {
        let handle = handle_at(ServiceStatus::Running);
        handle.inner.cell.request_stop();
        assert_eq!(handle.current(), ServiceStatus::Stopping);
        assert!(handle.stop_token().is_cancelled());
        // 重复请求:状态不变(不产生非法转换),不 panic
        handle.inner.cell.request_stop();
        assert_eq!(handle.current(), ServiceStatus::Stopping);
        // 已停止实例:无操作
        let stopped = handle_at(ServiceStatus::Stop);
        stopped.inner.cell.request_stop();
        assert_eq!(stopped.current(), ServiceStatus::Stop);
    }

    #[tokio::test]
    async fn wait_stop_normal_path_reports_stop() {
        let handle = handle_at(ServiceStatus::Running);
        let token = handle.stop_token();
        let inner = handle.clone();
        handle.spawn_task("service.test.normal", async move {
            token.cancelled().await;
            inner.just_change_status(ServiceStatus::Stop);
        });
        handle.wait_stop().await;
        assert_eq!(handle.current(), ServiceStatus::Stop);
    }

    #[tokio::test]
    async fn wait_stop_survives_task_panic_and_marks_failed() {
        let handle = handle_at(ServiceStatus::Staring);
        handle.spawn_task("service.test.panic", async move {
            panic!("service died silently");
        });
        handle.wait_stop().await;
        // 任务 panic:tracker 视为结束,状态未到终态 → 兜底 Failed
        assert_eq!(handle.current(), ServiceStatus::Failed);
        assert!(handle.stop_token().is_cancelled());
    }

    #[tokio::test]
    async fn wait_stop_abandoned_status_marks_failed() {
        let handle = handle_at(ServiceStatus::Running);
        let token = handle.stop_token();
        // 任务响应停止信号但未汇报终态就退出
        handle.spawn_task("service.test.abandoned", async move {
            token.cancelled().await;
        });
        handle.wait_stop().await;
        assert_eq!(handle.current(), ServiceStatus::Failed);
    }

    #[tokio::test]
    async fn silent_death_watcher_marks_failed() {
        let handle = handle_at(ServiceStatus::Staring);
        handle.supervise_lifecycle();
        let token = handle.stop_token();
        handle.spawn_task("service.test.silent", async move {
            // 既不响应信号也不汇报状态,直接退出
            drop(token);
        });
        handle.wait_for(|s| matches!(s, ServiceStatus::Failed)).await;
        assert!(handle.stop_token().is_cancelled());
    }

    #[tokio::test]
    async fn spawn_after_close_still_tracked() {
        let handle = handle_at(ServiceStatus::Running);
        handle.supervise_lifecycle();
        let token = handle.stop_token();
        let inner = handle.clone();
        // close 之后 spawn 的任务依然被追踪,wait_stop 会等它结束
        handle.spawn_task("service.test.late_spawn", async move {
            token.cancelled().await;
            inner.just_change_status(ServiceStatus::Stop);
        });
        handle.wait_stop().await;
        assert_eq!(handle.current(), ServiceStatus::Stop);
    }

    #[tokio::test]
    async fn wait_start_outcome_running() {
        let handle = handle_at(ServiceStatus::Staring);
        let inner = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            inner.just_change_status(ServiceStatus::Running);
        });
        assert_eq!(handle.wait_start_outcome(Duration::from_secs(5)).await, StartOutcome::Running);
    }

    #[tokio::test]
    async fn wait_start_outcome_failed() {
        let handle = handle_at(ServiceStatus::Staring);
        let inner = handle.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            inner.just_change_status(ServiceStatus::Failed);
        });
        assert_eq!(handle.wait_start_outcome(Duration::from_secs(5)).await, StartOutcome::Failed);
    }

    #[tokio::test]
    async fn wait_start_outcome_timeout() {
        let handle = handle_at(ServiceStatus::Staring);
        assert_eq!(
            handle.wait_start_outcome(Duration::from_millis(50)).await,
            StartOutcome::Timeout
        );
        // 超时后状态不变,调用方保留决策权
        assert_eq!(handle.current(), ServiceStatus::Staring);
    }

    #[tokio::test]
    async fn restart_creates_isolated_instances() {
        let first = handle_at(ServiceStatus::Running);
        let second = ServiceHandle::new();
        assert!(!ServiceHandle::ptr_eq(&first, &second));
        first.just_change_status(ServiceStatus::Stop);
        assert!(first.stop_token().is_cancelled());
        assert!(!second.stop_token().is_cancelled());
        assert_eq!(second.current(), ServiceStatus::Stop);
    }

    #[test]
    fn serialize_pins_wire_format() {
        // 线格式冻结:与直接序列化 ServiceStatus 逐字节一致,REST 协议不变
        for status in [
            ServiceStatus::Staring,
            ServiceStatus::Running,
            ServiceStatus::Stopping,
            ServiceStatus::Stop,
            ServiceStatus::Failed,
        ] {
            let handle = handle_at(status.clone());
            assert_eq!(
                serde_json::to_value(&handle).unwrap(),
                serde_json::to_value(&status).unwrap()
            );
        }
        assert_eq!(
            serde_json::to_value(handle_at(ServiceStatus::Running)).unwrap(),
            json!({"t":"running"})
        );
    }
}
