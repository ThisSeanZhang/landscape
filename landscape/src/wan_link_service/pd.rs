use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use uuid::Uuid;

use landscape_common::LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT;
use landscape_common::event::hub::IAPrefixEventSender;
use landscape_common::service::ServiceHandle;
use landscape_common::sys_service::route_service::RouteTargetInfo;
use landscape_common::wan_link::{
    LinkStateHandle, PdRuntime, RuntimeWanLinkPdConfig, SessionIface,
};
use landscape_common::wan_service::wan_chain::dataplane::WanChainDataplane;
use landscape_core::pd_prefix::IAPrefixMap;

use crate::sys_service::route::IpRouteService;

#[allow(clippy::too_many_arguments)]
pub(super) async fn run(
    link_id: Uuid,
    chain_id: u16,
    iface: SessionIface,
    config: RuntimeWanLinkPdConfig,
    service_status: ServiceHandle,
    route_service: IpRouteService,
    chain_dataplane: Arc<dyn WanChainDataplane>,
    prefix_map: IAPrefixMap,
    shared_wan_iid: Arc<u64>,
    prefix_sender: IAPrefixEventSender,
    pd_runtime: Arc<ArcSwap<PdRuntime>>,
    link_state: LinkStateHandle,
) {
    let wan_route_info = RouteTargetInfo {
        ifindex: iface.ifindex,
        weight: 1,
        mac: iface.mac,
        is_docker: false,
        iface_name: iface.iface_name.clone(),
        iface_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        default_route: true,
        gateway_ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        dev_only_nexthop: false,
    };

    crate::wan_service::ipv6pd_client::v6::dhcp_v6_pd_client(
        link_id,
        chain_id,
        iface.iface_name,
        iface.ifindex,
        iface.mac,
        config.mac,
        config.expected_pd_len,
        LANDSCAPE_DEFAULE_DHCP_V6_CLIENT_PORT,
        service_status,
        wan_route_info,
        route_service,
        chain_dataplane,
        prefix_map,
        shared_wan_iid,
        prefix_sender,
        pd_runtime,
        link_state,
    )
    .await;
}
