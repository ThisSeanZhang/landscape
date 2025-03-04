use landscape_ebpf::nat::{init_nat, NatConfig};
use tokio::sync::{oneshot, watch};

use crate::service::ServiceStatus;

pub async fn create_nat_service(
    ifindex: i32,
    has_mac: bool,
    nat_config: NatConfig,
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
        tracing::info!("等待外部停止信号");
        let _ = stop_wait.await;
        tracing::info!("接收外部停止信号");
        let _ = tx.send(());
        tracing::info!("向内部发送停止信号");
    });
    std::thread::spawn(move || {
        init_nat(ifindex, has_mac, rx, nat_config, None);
        tracing::info!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
    });
    let _ = other_rx.await;
    tracing::info!("结束外部线程阻塞");
    service_status.send_replace(ServiceStatus::Stop { message: None });
}
