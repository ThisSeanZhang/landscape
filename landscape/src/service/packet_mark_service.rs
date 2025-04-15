use landscape_common::service::ServiceStatus;
use landscape_common::{
    service::{service_manager::ServiceHandler, DefaultServiceStatus, DefaultWatchServiceStatus},
    store::storev2::LandScapeStore,
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

use crate::iface::get_iface_by_name;

#[derive(Clone)]
pub struct MarkService;

impl ServiceHandler for MarkService {
    type Status = DefaultServiceStatus;
    type Config = PacketMarkServiceConfig;

    async fn initialize(config: PacketMarkServiceConfig) -> DefaultWatchServiceStatus {
        let service_status = DefaultWatchServiceStatus::new();

        if config.enable {
            if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                tokio::spawn(async move {
                    create_mark_service(iface.index as i32, iface.mac.is_some(), status_clone).await
                });
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMarkServiceConfig {
    pub iface_name: String,
    pub enable: bool,
}

impl LandScapeStore for PacketMarkServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum WallRuleSource {
    Text { target_ip: [u8; 4], mask: u8 },
    GeoKey { key: String },
}

pub async fn create_mark_service(
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
        tracing::info!("启动 packet_mark 在 ifindex: {:?}", ifindex);
        // landscape_ebpf::packet_mark::init_packet_mark(ifindex, has_mac, rx);
        landscape_ebpf::flow::verdict::attach_verdict_flow(ifindex, has_mac, rx).unwrap();
        tracing::info!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
    });
    let _ = other_rx.await;
    tracing::info!("结束外部线程阻塞");
    service_status.just_change_status(ServiceStatus::Stop);
}
