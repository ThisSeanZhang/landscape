use tokio::time::{sleep, Duration};

use landscape_common::service::{ServiceStatus, WatchService};

use crate::pppoe_client::PPPoEClientConfig;

use super::error::PppoeError;

pub async fn run(config: PPPoEClientConfig, mut status_rx: WatchService) {
    status_rx.just_change_status(ServiceStatus::Staring);
    let Ok((mut pppoe_tx, mut pppoe_rx)) = landscape_ebpf::pppoe::start(config.index).await else {
        tracing::error!(
            iface_name = %config.iface_name,
            "PPPoE eBPF channel created fail"
        );

        status_rx.just_change_status(ServiceStatus::Stop);
        return;
    };

    tracing::info!(
        iface_name = %config.iface_name,
        "PPPoE client started, eBPF channel created"
    );

    let mut retry_count: u64 = 0;
    status_rx.just_change_status(ServiceStatus::Running);
    // MAIN LOOP
    loop {
        if retry_count > 0 {
            let mins = (5 * retry_count).min(30);
            tokio::select! {
                _ = sleep(Duration::from_secs(mins * 60)) => {},
                _ = status_rx.wait_to_stopping() => {
                    status_rx.just_change_status(ServiceStatus::Stop);
                    break
                },
            }
        }

        if pppoe_rx.is_closed() {
            let Ok((new_pppoe_tx, new_pppoe_rx)) = landscape_ebpf::pppoe::start(config.index).await
            else {
                tracing::error!(
                    iface_name = %config.iface_name,
                    "PPPoE eBPF channel created fail, retry"
                );
                retry_count += 1;
                continue;
            };
            pppoe_tx = new_pppoe_tx;
            pppoe_rx = new_pppoe_rx;
        }
    }
}
