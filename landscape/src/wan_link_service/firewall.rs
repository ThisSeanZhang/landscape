use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{RuntimeWanLinkFirewallConfig, SessionIface, swap_if_changed};
use landscape_common::wan_service::wan_chain::dataplane::WanChainDataplane;

pub(super) async fn run(
    chain_id: u16,
    iface: SessionIface,
    _config: RuntimeWanLinkFirewallConfig,
    service_status: ServiceHandle,
    dataplane: Arc<dyn WanChainDataplane>,
    runtime: Arc<ArcSwap<ServiceStatus>>,
) {
    let firewall = match dataplane.attach_firewall(chain_id, iface.ifindex, iface.has_eth_header())
    {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start firewall for {}: {err}", iface.iface_name);
            service_status.just_change_status(ServiceStatus::Failed);
            swap_if_changed(&runtime, ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    swap_if_changed(&runtime, ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    drop(firewall);

    service_status.just_change_status(ServiceStatus::Stop);
    swap_if_changed(&runtime, ServiceStatus::Stop);
}
