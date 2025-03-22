use landscape_common::{
    service::{
        service_manager::ServiceHandler, DefaultServiceStatus, DefaultWatchServiceStatus,
        ServiceStatus,
    },
    store::storev2::LandScapeStore,
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::iface::get_iface_by_name;

pub mod rules;

#[derive(Clone)]
pub struct FirewallService;

impl ServiceHandler for FirewallService {
    type Status = DefaultServiceStatus;

    type Config = FirewallServiceConfig;

    async fn initialize(config: FirewallServiceConfig) -> DefaultWatchServiceStatus {
        let service_status = DefaultWatchServiceStatus::new();
        // service_status.just_change_status(ServiceStatus::Staring);

        if config.enable {
            // 具体的 NAT 服务启动逻辑
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                tokio::spawn(async move {
                    create_firewall_service(iface.index as i32, iface.mac.is_some(), status_clone)
                        .await
                });
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallServiceConfig {
    pub iface_name: String,
    pub enable: bool,
}

impl LandScapeStore for FirewallServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

pub async fn create_firewall_service(
    ifindex: i32,
    has_mac: bool,
    service_status: DefaultWatchServiceStatus,
) {
    service_status.just_change_status(ServiceStatus::Staring);
    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();
    service_status.just_change_status(ServiceStatus::Running);
    let service_status_clone = service_status.clone();
    tokio::spawn(async move {
        let stop_wait = service_status_clone.wait_to_stopping();
        tracing::info!("等待外部停止信号");
        let _ = stop_wait.await;
        tracing::info!("接收外部停止信号");
        let _ = tx.send(());
        tracing::info!("向内部发送停止信号");
    });
    std::thread::spawn(move || {
        if let Err(e) = landscape_ebpf::firewall::new_firewall(ifindex, has_mac, rx) {
            tracing::error!("{e:?}");
        }
        tracing::info!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
    });
    let _ = other_rx.await;
    tracing::info!("结束外部线程阻塞");
    service_status.just_change_status(ServiceStatus::Stop);
}
