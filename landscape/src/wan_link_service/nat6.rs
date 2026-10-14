use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{LinkState, SessionIface, WanV6Prefix, swap_if_changed};
use landscape_common::wan_service::wan_chain::dataplane::WanChainDataplane;
use tokio::sync::watch;

/// The v6 NAT section.  The WAN prefix is published on the link state
/// watch by the PD section without bumping the session epoch, so the
/// runner re-attaches the stage itself whenever the prefix changes:
/// lease/epoch churn is handled by the supervisor restart, prefix churn
/// by the loop below.  A cleared prefix re-bakes the unconfigured
/// (drop) prefix instead of detaching, preserving the old map-miss
/// semantics.
pub(super) async fn run(
    chain_id: u16,
    iface: SessionIface,
    mut state_rx: watch::Receiver<LinkState>,
    service_status: ServiceHandle,
    dataplane: Arc<dyn WanChainDataplane>,
    runtime: Arc<ArcSwap<ServiceStatus>>,
) {
    fn prefix_of(state: &LinkState) -> Option<(std::net::Ipv6Addr, u8)> {
        state.session.v6_prefix.map(|WanV6Prefix { prefix_ip, prefix_len }| (prefix_ip, prefix_len))
    }

    let mut prefix = prefix_of(&state_rx.borrow_and_update());
    let mut nat =
        match dataplane.attach_nat6(chain_id, iface.ifindex, iface.has_eth_header(), prefix) {
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

        let new_prefix = prefix_of(&state_rx.borrow_and_update());
        if new_prefix == prefix {
            continue;
        }
        prefix = new_prefix;
        drop(nat);
        nat = match dataplane.attach_nat6(chain_id, iface.ifindex, iface.has_eth_header(), prefix) {
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
