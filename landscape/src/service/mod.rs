use serde::{Serialize, Serializer};
use tokio::sync::watch;
use tracing::info;

pub mod ipconfig;
pub mod nat_service;
pub mod packet_mark_service;
pub mod pppd_service;

#[derive(Clone, Debug)]
pub struct WatchServiceStatus(pub watch::Sender<ServiceStatus>);

impl Default for WatchServiceStatus {
    fn default() -> Self {
        let (sender, _) = watch::channel(ServiceStatus::Stop { message: None });
        Self(sender)
    }
}

impl WatchServiceStatus {
    pub async fn stop(&self) {
        wait_status_stop(&self.0).await;
    }

    pub async fn wait_start(&self) {
        wait_status_running(&self.0).await;
    }
}

#[derive(Serialize, Debug, PartialEq, Clone)]
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
    Stop { message: Option<String> },
}

impl Serialize for WatchServiceStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.borrow().serialize(serializer)
    }
}

async fn wait_status_stop(ip_service_status: &watch::Sender<ServiceStatus>) {
    let mut do_wait = false;
    ip_service_status.send_if_modified(|status| {
        info!("当前服务的状态: {:?}", status);
        // 修改当前状态, 并决定是否进行等待
        match status {
            ServiceStatus::Staring | ServiceStatus::Running => {
                *status = ServiceStatus::Stopping;
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
    info!("当前需要等待之前状态结束吗?: {do_wait}");
    if do_wait {
        info!("那么进行等待");
        // 等待已有 IP 配置服务停止
        let _ = ip_service_status
            .subscribe()
            .wait_for(|status| matches!(status, ServiceStatus::Stop { .. }))
            .await;
        info!("前一个服务等待停止结束");
    }
    // let _ = drop(do_wait);
}

async fn wait_status_running(ip_service_status: &watch::Sender<ServiceStatus>) {
    let mut do_wait = false;

    if matches!(*ip_service_status.borrow(), ServiceStatus::Staring) {
        do_wait = true;
    }
    if do_wait {
        let _ = ip_service_status
            .subscribe()
            .wait_for(|status| matches!(status, ServiceStatus::Running))
            .await;
    }
}
