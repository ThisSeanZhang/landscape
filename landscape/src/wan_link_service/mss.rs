use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{RuntimeWanLinkMssConfig, SessionIface, swap_if_changed};
use landscape_ebpf::chain::wan_link::WanLinkDataplane;

pub(super) async fn run(
    iface: SessionIface,
    config: RuntimeWanLinkMssConfig,
    service_status: ServiceHandle,
    dataplane: Arc<WanLinkDataplane>,
    runtime: Arc<ArcSwap<ServiceStatus>>,
) {
    let mss_clamp =
        match dataplane.attach_mss(iface.ifindex, config.clamp_size, iface.has_eth_header()) {
            Ok(handle) => handle,
            Err(err) => {
                tracing::error!("failed to start mss clamp for {}: {err}", iface.iface_name);
                service_status.just_change_status(ServiceStatus::Failed);
                swap_if_changed(&runtime, ServiceStatus::Failed);
                return;
            }
        };

    service_status.just_change_status(ServiceStatus::Running);
    swap_if_changed(&runtime, ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    drop(mss_clamp);

    service_status.just_change_status(ServiceStatus::Stop);
    swap_if_changed(&runtime, ServiceStatus::Stop);
}
