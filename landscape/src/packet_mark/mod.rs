use landscape_common::mark::PacketMark;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch};

use crate::service::ServiceStatus;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Mark 标记的配置
pub struct MarkRuleConfig {
    pub name: String,
    // 优先级
    pub index: u32,
    // IP 来源
    pub source: Vec<WallRuleSource>,

    pub mark: PacketMark,
}

impl Default for MarkRuleConfig {
    fn default() -> Self {
        Self {
            name: "default rule".into(),
            index: 10000,
            mark: Default::default(),
            source: vec![],
        }
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
    service_status: watch::Sender<ServiceStatus>,
) {
    service_status.send_replace(ServiceStatus::Staring);
    let (tx, rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();
    service_status.send_replace(ServiceStatus::Running);
    let mut service_status_receiver = service_status.subscribe();
    tokio::spawn(async move {
        let stop_wait = service_status_receiver.wait_for(|status| {
            matches!(status, ServiceStatus::Stopping)
                || matches!(status, ServiceStatus::Stop { .. })
        });
        println!("等待外部停止信号");
        let _ = stop_wait.await;
        println!("接收外部停止信号");
        let _ = tx.send(());
        println!("向内部发送停止信号");
    });
    std::thread::spawn(move || {
        println!("启动 packet_mark 在 ifindex: {:?}", ifindex);
        landscape_ebpf::packet_mark::init_packet_mark(ifindex, has_mac, rx);
        println!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
    });
    let _ = other_rx.await;
    println!("结束外部线程阻塞");
    service_status.send_replace(ServiceStatus::Stop { message: None });
}
