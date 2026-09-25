use std::sync::Arc;

use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;

/// Firewall service body, driven by the WAN link runtime's firewall section.
pub async fn create_firewall_service(
    iface_name: String,
    ifindex: i32,
    link_chain_id: u16,
    has_mac: bool,
    service_status: WatchService,
    dataplane: Arc<dyn FirewallDataplane>,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let firewall = match dataplane.attach(ifindex as u32, link_chain_id, has_mac) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start firewall for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Received external stop signal");

    drop(firewall);

    service_status.just_change_status(ServiceStatus::Stop);
}
