use std::sync::Arc;

use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::wan_service::mss_clamp::dataplane::MssClampDataplane;

/// MSS clamp service body, driven by the WAN link runtime's mss section.
pub async fn run_mss_clamp(
    iface_name: String,
    ifindex: i32,
    link_chain_id: u16,
    mtu_size: u16,
    has_mac: bool,
    service_status: WatchService,
    dataplane: Arc<dyn MssClampDataplane>,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let mss_clamp = match dataplane.attach(ifindex as u32, link_chain_id, mtu_size, has_mac) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start mss clamp for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Stop);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Received external stop signal");

    drop(mss_clamp);

    service_status.just_change_status(ServiceStatus::Stop);
}
