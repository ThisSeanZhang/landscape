use std::sync::Arc;

use landscape_common::service::{ServiceStatus, WatchService};
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::nat::dataplane::NatDataplane;

/// NAT service body, driven by the WAN link runtime's NAT section.
pub async fn create_nat_service(
    iface_name: String,
    ifindex: i32,
    has_mac: bool,
    nat_config: NatConfig,
    service_status: WatchService,
    dataplane: Arc<dyn NatDataplane>,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let nat = match dataplane.attach(ifindex as u32, has_mac, &nat_config) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start nat for {iface_name}: {err}");
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    tracing::info!("Waiting for external stop signal");
    let _ = service_status.wait_to_stopping().await;
    tracing::info!("Received external stop signal");

    drop(nat);

    service_status.just_change_status(ServiceStatus::Stop);
}
