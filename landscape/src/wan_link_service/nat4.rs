use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{RuntimeWanLinkNatConfig, SessionIface, swap_if_changed};
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::wan_chain::dataplane::WanChainDataplane;

/// The v4 NAT section.  The lease address arrives via the session state
/// (a lease change bumps the session epoch, so the supervisor restarts
/// this section with the new value already in place); it is baked into
/// the NAT objects' rodata at attach time.
pub(super) async fn run(
    chain_id: u16,
    iface: SessionIface,
    config: RuntimeWanLinkNatConfig,
    wan_addr: Ipv4Addr,
    service_status: ServiceHandle,
    dataplane: Arc<dyn WanChainDataplane>,
    runtime: Arc<ArcSwap<ServiceStatus>>,
) {
    let nat_config = NatConfig {
        tcp_range: config.tcp_range,
        udp_range: config.udp_range,
        icmp_in_range: config.icmp_in_range,
    };
    let nat = match dataplane.attach_nat4(
        chain_id,
        iface.ifindex,
        iface.has_eth_header(),
        &nat_config,
        wan_addr,
    ) {
        Ok(handle) => handle,
        Err(err) => {
            tracing::error!("failed to start nat4 for {}: {err}", iface.iface_name);
            service_status.just_change_status(ServiceStatus::Failed);
            swap_if_changed(&runtime, ServiceStatus::Failed);
            return;
        }
    };

    service_status.just_change_status(ServiceStatus::Running);
    swap_if_changed(&runtime, ServiceStatus::Running);
    service_status.stop_token().cancelled().await;

    drop(nat);

    service_status.just_change_status(ServiceStatus::Stop);
    swap_if_changed(&runtime, ServiceStatus::Stop);
}
