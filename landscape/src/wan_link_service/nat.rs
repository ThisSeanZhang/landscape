use std::sync::Arc;

use landscape_common::dev::LandscapeInterface;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::RuntimeWanLinkNatConfig;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::nat::dataplane::NatDataplane;

pub(super) async fn run(
    iface: LandscapeInterface,
    config: RuntimeWanLinkNatConfig,
    service_status: ServiceHandle,
    dataplane: Arc<dyn NatDataplane>,
) {
    let nat_config = NatConfig {
        tcp_range: config.tcp_range,
        udp_range: config.udp_range,
        icmp_in_range: config.icmp_in_range,
    };
    let nat = match dataplane.attach(iface.index, iface.mac.is_some(), &nat_config) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start nat for {}: {err}", iface.name);
            service_status.just_change_status(ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    drop(nat);

    service_status.just_change_status(ServiceStatus::Stop);
}
