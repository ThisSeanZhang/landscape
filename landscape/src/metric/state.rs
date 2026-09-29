use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use landscape_common::service::ServiceStatus;

/// metric 服务的运行状态(metric 专属展示结构,仅复用 [`ServiceStatus`]
/// 枚举):纯状态机,无取消信号、无任务追踪——metric 的停止语义由事件源
/// 自身的 `stop_with_budget` 提供,状态只负责展示与防呆。
///
/// 与带 token/tracker 的运行句柄不同,本结构可在 start/stop 周期间复用
/// (不存在"进入退出态即永久死亡"的约束)。
#[derive(Clone, Default)]
pub struct MetricStatus {
    inner: Arc<RwLock<ServiceStatus>>,
}

impl MetricStatus {
    pub fn new() -> Self {
        Self::default()
    }

    /// 锁中毒恢复:临界区内无用户代码,状态值仍可用
    fn read(&self) -> RwLockReadGuard<'_, ServiceStatus> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write(&self) -> RwLockWriteGuard<'_, ServiceStatus> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    pub fn current(&self) -> ServiceStatus {
        self.read().clone()
    }

    /// 是否已落到终态(Stop/Failed)
    pub fn is_stop(&self) -> bool {
        matches!(*self.read(), ServiceStatus::Stop | ServiceStatus::Failed)
    }

    /// 是否活跃(Staring/Running)
    pub fn is_active(&self) -> bool {
        matches!(*self.read(), ServiceStatus::Staring | ServiceStatus::Running)
    }

    /// 状态汇报(严格):同状态幂等 no-op;非法转换 warn 并拒绝
    /// (转换矩阵来自 [`ServiceStatus::can_transition_to`])。
    pub fn just_change_status(&self, new_status: ServiceStatus) {
        let mut guard = self.write();
        if *guard == new_status {
            return;
        }
        if !guard.can_transition_to(&new_status) {
            return;
        }
        tracing::debug!("metric service status changed to {new_status:?}");
        *guard = new_status;
    }
}
