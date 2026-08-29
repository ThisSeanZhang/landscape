use std::fmt::Debug;

use serde::Serialize;
use tokio::sync::watch;

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
    // 异常停止
    Failed,
}

impl ServiceStatus {
    // 检查当前状态是否可以转换到目标状态
    pub fn can_transition_to(&self, target: &ServiceStatus) -> bool {
        let can = matches!(
            (self, target),
            (ServiceStatus::Stop, ServiceStatus::Staring)
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
}

/// 被观测的服务
#[derive(Clone, Debug)]
pub struct WatchService(pub watch::Sender<ServiceStatus>);

impl Default for WatchService {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchService {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(ServiceStatus::default());
        Self(sender)
    }

    pub fn just_change_status(&self, new_status: ServiceStatus) {
        self.0.send_if_modified(|current| {
            if current.can_transition_to(&new_status) {
                tracing::debug!("status changed to {new_status:?}");
                *current = new_status;
                true
            } else {
                false
            }
        });
    }

    pub fn is_exit(&self) -> bool {
        matches!(
            *self.0.borrow(),
            ServiceStatus::Stopping | ServiceStatus::Stop | ServiceStatus::Failed
        )
    }

    pub fn is_running(&self) -> bool {
        matches!(*self.0.borrow(), ServiceStatus::Running)
    }

    pub fn is_stop(&self) -> bool {
        matches!(*self.0.borrow(), ServiceStatus::Stop | ServiceStatus::Failed)
    }

    pub fn is_active(&self) -> bool {
        matches!(*self.0.borrow(), ServiceStatus::Staring | ServiceStatus::Running)
    }

    pub fn current(&self) -> ServiceStatus {
        self.0.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<ServiceStatus> {
        self.0.subscribe()
    }

    pub async fn changed(&self) -> Result<(), watch::error::RecvError> {
        self.0.subscribe().changed().await
    }

    /// Will not send stop
    pub async fn wait_to_stopping(&self) {
        let _ =
            self.0.subscribe().wait_for(|status| matches!(status, ServiceStatus::Stopping)).await;
    }

    /// will send `stopping` to service, and wait until stop
    pub async fn wait_stop(&self) {
        wait_status_stop(&self.0).await;
    }

    pub async fn wait_start(&self) {
        wait_status_running(&self.0).await;
    }
}

async fn wait_status_stop(sender: &watch::Sender<ServiceStatus>) {
    let mut do_wait = false;
    sender.send_if_modified(|status| {
        tracing::debug!("current status: {status:?}, requesting stop");
        match status {
            ServiceStatus::Staring | ServiceStatus::Running => {
                if status.can_transition_to(&ServiceStatus::Stopping) {
                    *status = ServiceStatus::Stopping;
                }
                do_wait = true;
                true
            }
            ServiceStatus::Stopping => {
                do_wait = true;
                false
            }
            ServiceStatus::Stop | ServiceStatus::Failed => {
                do_wait = false;
                false
            }
        }
    });
    if do_wait {
        tracing::debug!("waiting for service to stop");
        let _ = sender
            .subscribe()
            .wait_for(|status| matches!(status, ServiceStatus::Stop | ServiceStatus::Failed))
            .await;
        tracing::debug!("service stopped");
    }
}

async fn wait_status_running(sender: &watch::Sender<ServiceStatus>) {
    if matches!(*sender.borrow(), ServiceStatus::Staring) {
        tracing::debug!("waiting for service to start");
        let _ =
            sender.subscribe().wait_for(|status| matches!(status, ServiceStatus::Running)).await;
        tracing::debug!("service started");
    }
}

impl Serialize for WatchService {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.borrow().serialize(serializer)
    }
}
