mod driver;
mod fsm;
mod message;
mod socket;
mod system;

#[cfg(test)]
mod test_driver;
#[cfg(test)]
mod test_fsm;

use arc_swap::ArcSwap;
use landscape_common::net::MacAddr;
use landscape_common::service::ServiceHandle;
use landscape_common::wan_link::{LinkStateHandle, V4Runtime};
use landscape_ebpf::chain::wan_link::WanLinkDataplane;
use std::sync::Arc;
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

#[derive(Clone)]
pub struct DhcpV4ClientServiceRuntimeConfig {
    pub link_id: Uuid,
    pub chain_id: u16,
    pub ifindex: u32,
    pub iface_name: String,
    pub mac_addr: MacAddr,
    pub client_port: u16,
    pub hostname: String,
    pub default_router: bool,
}

pub struct DhcpV4ClientServices {
    pub route_service: IpRouteService,
    pub chain_dataplane: Arc<WanLinkDataplane>,
    pub session: Option<LinkStateHandle>,
    pub runtime: Arc<ArcSwap<V4Runtime>>,
}

pub async fn run(
    config: DhcpV4ClientServiceRuntimeConfig,
    services: DhcpV4ClientServices,
    service_status: ServiceHandle,
) {
    driver::run(config, services, service_status).await
}
