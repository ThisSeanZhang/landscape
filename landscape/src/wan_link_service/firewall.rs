use std::sync::Arc;

use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{RuntimeWanLinkFirewallConfig, SessionIface};
use landscape_common::wan_service::firewall::dataplane::FirewallDataplane;

pub(super) async fn run(
    iface: SessionIface,
    _config: RuntimeWanLinkFirewallConfig,
    service_status: ServiceHandle,
    dataplane: Arc<dyn FirewallDataplane>,
) {
    let firewall = match dataplane.attach(iface.ifindex, iface.has_mac()) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start firewall for {}: {err}", iface.iface_name);
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    drop(firewall);

    service_status.just_change_status(ServiceStatus::Stop);
}
