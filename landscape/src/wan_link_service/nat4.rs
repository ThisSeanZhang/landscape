use std::net::Ipv4Addr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use landscape_common::service::{ServiceHandle, ServiceStatus};
use landscape_common::wan_link::{RuntimeWanLinkNatConfig, SessionIface, swap_if_changed};
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_database::static_nat_mapping_v4::repository::StaticNatMappingV4Repository;
use landscape_ebpf::chain::wan_link::WanLinkDataplane;
use tokio::sync::broadcast;

/// The v4 NAT section. The lease address and static mappings are baked into
/// the NAT objects at attach time. Static configuration changes are observed
/// outside the stage; the section re-reads the repository and restarts NAT so
/// its array and queues are rebuilt from the latest database state.
#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    iface: SessionIface,
    config: RuntimeWanLinkNatConfig,
    wan_addr: Ipv4Addr,
    service_status: ServiceHandle,
    dataplane: Arc<WanLinkDataplane>,
    runtime: Arc<ArcSwap<ServiceStatus>>,
    static_nat4_store: StaticNatMappingV4Repository,
    mut static_events: broadcast::Receiver<()>,
) {
    let nat_config = NatConfig {
        tcp_range: config.tcp_range,
        udp_range: config.udp_range,
        icmp_in_range: config.icmp_in_range,
    };
    let stop_token = service_status.stop_token();
    let mut last_static_configs = Vec::new();

    loop {
        if stop_token.is_cancelled() {
            break;
        }

        match static_nat4_store.list_runtime_configs_v4().await {
            Ok(configs) => last_static_configs = configs,
            Err(error) => {
                tracing::error!(
                    "failed to load static nat4 configs for {}: {error:?}",
                    iface.iface_name
                );
            }
        }

        let nat = match dataplane.attach_nat4(
            iface.ifindex,
            iface.has_eth_header(),
            &nat_config,
            wan_addr,
            &last_static_configs,
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

        tokio::select! {
            _ = stop_token.cancelled() => {
                drop(nat);
                break;
            }
            event = static_events.recv() => {
                drop(nat);
                match event {
                    Ok(()) | Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    service_status.just_change_status(ServiceStatus::Stop);
    swap_if_changed(&runtime, ServiceStatus::Stop);
}
