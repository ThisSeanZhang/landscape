use std::fmt::Debug;

use serde::Serialize;

use landscape_macro::LdApiError;
use service_code::{WatchService, Watchable};

// pub mod controller_service;
pub mod controller_service_v2;
pub mod service_code;
// pub mod service_manager;
pub mod service_manager_v2;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum ServiceConfigError {
    #[error("{service_name} service config not found")]
    #[api_error(id = "service.config_not_found", status = 404)]
    NotFound { service_name: &'static str },
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
}

impl ServiceStatus {
    // 检查当前状态是否可以转换到目标状态
    pub fn can_transition_to(&self, target: &ServiceStatus) -> bool {
        let can = matches!(
            (self, target),
            (ServiceStatus::Stop, ServiceStatus::Staring)
                | (ServiceStatus::Staring, ServiceStatus::Running)
                | (ServiceStatus::Staring, ServiceStatus::Stopping)
                | (ServiceStatus::Staring, ServiceStatus::Stop)
                | (ServiceStatus::Running, ServiceStatus::Stopping)
                | (ServiceStatus::Running, ServiceStatus::Stop)
                | (ServiceStatus::Stopping, ServiceStatus::Stop)
        );
        if !can {
            tracing::error!(
                "can not change status, current status: {self:?}, target status: {target:?}"
            );
        }
        can
    }
}

#[derive(Serialize, Debug, PartialEq, Clone, Default)]
pub struct DefaultServiceStatus(pub ServiceStatus);

impl Watchable for DefaultServiceStatus {
    type HoldData = ();
    fn get_current_status_code(&self) -> ServiceStatus {
        self.0.clone()
    }

    fn change_status(&mut self, new_status: ServiceStatus, data: Option<()>) -> bool {
        let _ = data;
        if self.0.can_transition_to(&new_status) {
            tracing::debug!("change to new status: {new_status:?}");
            self.0 = new_status;
        }
        true
    }
}

/// 默认定义的服务监听
pub type DefaultWatchServiceStatus = WatchService<DefaultServiceStatus>;
