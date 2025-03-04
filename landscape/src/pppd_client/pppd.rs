use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::Command;
use std::process::Stdio;

use tokio::sync::{oneshot, watch};

use super::PPPDConfig;
use crate::service::ServiceStatus;

pub async fn create_pppd_thread(
    attach_iface_name: String,
    ppp_iface_name: String,
    pppd_conf: PPPDConfig,
    service_status: watch::Sender<ServiceStatus>,
) {
    service_status.send_replace(ServiceStatus::Staring);

    let (tx, mut rx) = oneshot::channel::<()>();
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

    let Ok(_) = pppd_conf.write_config(&attach_iface_name, &ppp_iface_name) else {
        tracing::error!("pppd 配置写入失败");
        service_status.send_replace(ServiceStatus::Stop { message: None });
        return;
    };

    let (updata_ip, mut updata_ip_rx) = watch::channel(());
    let ppp_iface_name_clone = ppp_iface_name.clone();
    tokio::spawn(async move {
        let mut ip4addr: Option<(u32, HashSet<Ipv4Addr>)> = None;
        while let Ok(_) = updata_ip_rx.changed().await {
            let new_ip4addr = crate::get_address(&ppp_iface_name_clone).await;
            if let Some(new_ip4addr) = new_ip4addr {
                let update = if let Some(data) = ip4addr { data != new_ip4addr } else { true };
                if update {
                    for ip in new_ip4addr.1.iter() {
                        landscape_ebpf::map_setting::add_wan_ip(new_ip4addr.0, ip.clone());
                    }
                }
                ip4addr = Some(new_ip4addr);
            }
        }
    });

    tracing::info!("pppd 配置写入成功");
    std::thread::spawn(move || {
        tracing::info!("pppd 启动中");
        let mut child = match Command::new("pppd")
            .arg("nodetach")
            .arg("call")
            .arg(&ppp_iface_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing::error!("启动 pppd 失败: {}", e);
                return;
            }
        };
        let mut check_error_times = 0;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            updata_ip.send_replace(());
            match child.try_wait() {
                Ok(Some(status)) => {
                    tracing::warn!("pppd 退出， 状态码： {:?}", status);
                    break;
                }
                Ok(None) => {
                    check_error_times = 0;
                }
                Err(e) => {
                    tracing::error!("pppd error: {e:?}");
                    if check_error_times > 3 {
                        break;
                    }
                    check_error_times += 1;
                }
            }

            match rx.try_recv() {
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                Ok(_) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    tracing::error!("rx, 通知错误");
                    break;
                }
            }
        }
        let _ = child.kill();
        tracing::info!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
        pppd_conf.delete_config(&ppp_iface_name);
    });

    let _ = other_rx.await;
    tracing::info!("结束外部线程阻塞");
    service_status.send_replace(ServiceStatus::Stop { message: None });
}
