use std::fmt::Debug;

use serde::Serialize;
use tokio::sync::watch;

use super::ServiceStatus;

pub trait Watchable {
    type HoleData;
    fn get_current_status_code(&self) -> ServiceStatus;

    fn modify_curent_status(&mut self, status: ServiceStatus);

    fn change_status(&mut self, new_status: ServiceStatus, data: Option<Self::HoleData>) -> bool;
}

pub trait WatchServiceTrait: Clone + Serialize + Default + Watchable {}
impl<T> WatchServiceTrait for T where T: Clone + Serialize + Default + Debug + Watchable {}

/// 被观测的服务
#[derive(Clone, Debug)]
pub struct WatchService<T: WatchServiceTrait>(pub watch::Sender<T>);

impl<T: WatchServiceTrait> WatchService<T> {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(T::default());
        Self(sender)
    }

    pub fn send_replace(&self, status: T) -> T {
        self.0.send_replace(status)
    }

    pub fn just_change_status(&self, new_status: ServiceStatus) {
        self.0.send_if_modified(|current| current.change_status(new_status, None));
    }

    pub fn change_status_with_data(&self, new_status: ServiceStatus, data: Option<T::HoleData>) {
        self.0.send_if_modified(|current| current.change_status(new_status, data));
    }

    pub fn is_exit(&self) -> bool {
        let inner = self.0.borrow();
        let status = inner.get_current_status_code();
        match status {
            ServiceStatus::Stopping | ServiceStatus::Stop => true,
            _ => false,
        }
    }

    pub fn is_stop(&self) -> bool {
        let inner = self.0.borrow();
        let status = inner.get_current_status_code();
        match status {
            ServiceStatus::Stop => true,
            _ => false,
        }
    }

    pub fn subscribe(&self) -> watch::Receiver<T> {
        self.0.subscribe()
    }

    pub fn send_if_modified<F>(&self, function: F) -> bool
    where
        F: FnOnce(&mut T) -> bool,
    {
        self.0.send_if_modified(function)
    }

    pub async fn changed(&self) -> Result<(), watch::error::RecvError> {
        self.0.subscribe().changed().await
    }

    pub async fn wait_to_stopping(&self) {
        let _ = self
            .0
            .subscribe()
            .wait_for(|status| matches!(status.get_current_status_code(), ServiceStatus::Stopping))
            .await;
    }

    /// will send `stopping` to service, and wait until stop
    pub async fn wait_stop(&self) {
        wait_status_stop(&self.0).await;
    }

    pub async fn wait_start(&self) {
        wait_status_running(&self.0).await;
    }
}

async fn wait_status_stop<T: WatchServiceTrait>(ip_service_status: &watch::Sender<T>) {
    let mut do_wait = false;
    ip_service_status.send_if_modified(|watch_status| {
        let status = watch_status.get_current_status_code();
        tracing::info!("当前服务的状态: {:?}", status);
        // 修改当前状态, 并决定是否进行等待
        match status {
            ServiceStatus::Staring | ServiceStatus::Running => {
                watch_status.modify_curent_status(ServiceStatus::Stopping);
                do_wait = true;
                true
            }
            ServiceStatus::Stopping => {
                do_wait = true;
                false
            }
            ServiceStatus::Stop { .. } => {
                do_wait = false;
                false
            }
        }
    });
    tracing::info!("当前需要等待之前状态结束吗?: {do_wait}");
    if do_wait {
        tracing::info!("那么进行等待");
        // 等待已有 IP 配置服务停止
        let _ = ip_service_status
            .subscribe()
            .wait_for(|status| matches!(status.get_current_status_code(), ServiceStatus::Stop))
            .await;
        tracing::info!("前一个服务等待停止结束");
    }
    // let _ = drop(do_wait);
}

async fn wait_status_running<T: WatchServiceTrait>(ip_service_status: &watch::Sender<T>) {
    let mut do_wait = false;

    let status = ip_service_status.borrow().get_current_status_code();
    if matches!(status, ServiceStatus::Staring) {
        do_wait = true;
    }
    if do_wait {
        let _ = ip_service_status
            .subscribe()
            .wait_for(|status| matches!(status.get_current_status_code(), ServiceStatus::Running))
            .await;
    }
}

impl<T: WatchServiceTrait> Serialize for WatchService<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.borrow().serialize(serializer)
    }
}
