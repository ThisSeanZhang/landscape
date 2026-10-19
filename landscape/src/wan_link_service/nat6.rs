use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{LinkState, SessionIface, WanV6Prefix, swap_if_changed};
use landscape_ebpf::chain::wan_link::WanLinkDataplane;
use tokio::sync::watch;

/// The v6 NAT section.  The WAN prefix is published on the link state
/// watch by the PD section without bumping the session epoch, so the
/// runner re-attaches the stage itself whenever the prefix changes:
/// lease/epoch churn is handled by the supervisor restart, prefix churn
/// by the loop below.  A cleared prefix re-bakes the unconfigured
/// (drop) prefix instead of detaching, preserving the old map-miss
/// semantics.
pub(super) async fn run(
    iface: SessionIface,
    mut state_rx: watch::Receiver<LinkState>,
    service_status: ServiceHandle,
    dataplane: Arc<WanLinkDataplane>,
    runtime: Arc<ArcSwap<ServiceStatus>>,
) {
    fn lease_of(
        state: &LinkState,
    ) -> (Option<(std::net::Ipv6Addr, u8)>, Option<std::net::Ipv6Addr>) {
        (
            state
                .session
                .v6_prefix
                .map(|WanV6Prefix { prefix_ip, prefix_len }| (prefix_ip, prefix_len)),
            state.session.wan_v6_addr,
        )
    }

    let (mut prefix, mut wan_addr) = lease_of(&state_rx.borrow_and_update());
    let mut nat =
        match dataplane.attach_nat6(iface.ifindex, iface.has_eth_header(), prefix, wan_addr) {
            Ok(handle) => handle,
            Err(err) => {
                tracing::error!("failed to start nat6 for {}: {err}", iface.iface_name);
                service_status.just_change_status(ServiceStatus::Failed);
                swap_if_changed(&runtime, ServiceStatus::Failed);
                return;
            }
        };

    service_status.just_change_status(ServiceStatus::Running);
    swap_if_changed(&runtime, ServiceStatus::Running);

    let stop = service_status.stop_token();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            changed = state_rx.changed() => {
                if changed.is_err() {
                    break;
                }
            }
        }

        let (new_prefix, new_wan_addr) = lease_of(&state_rx.borrow_and_update());
        if new_prefix == prefix && new_wan_addr == wan_addr {
            continue;
        }
        prefix = new_prefix;
        wan_addr = new_wan_addr;
        drop(nat);
        nat = match dataplane.attach_nat6(iface.ifindex, iface.has_eth_header(), prefix, wan_addr) {
            Ok(handle) => handle,
            Err(err) => {
                tracing::error!("failed to re-attach nat6 for {}: {err}", iface.iface_name);
                service_status.just_change_status(ServiceStatus::Failed);
                swap_if_changed(&runtime, ServiceStatus::Failed);
                return;
            }
        };
    }

    drop(nat);

    service_status.just_change_status(ServiceStatus::Stop);
    swap_if_changed(&runtime, ServiceStatus::Stop);
}
