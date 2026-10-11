mod driver;
mod fsm;
mod message;
mod socket;
mod system;

#[cfg(test)]
mod test_driver;
#[cfg(test)]
mod test_fsm;

use landscape_common::net::MacAddr;
use landscape_common::service::ServiceHandle;
use landscape_common::wan_link::LinkStateHandle;
use landscape_common::wan_service::addr_binding::WanAddrBinding;
use std::sync::Arc;
use uuid::Uuid;

use crate::sys_service::route::IpRouteService;

#[derive(Clone)]
pub struct DhcpV4ClientServiceRuntimeConfig {
    pub link_id: Uuid,
    pub ifindex: u32,
    pub iface_name: String,
    pub mac_addr: MacAddr,
    pub client_port: u16,
    pub hostname: String,
    pub default_router: bool,
}

pub struct DhcpV4ClientServices {
    pub route_service: IpRouteService,
    pub addr_binding: Arc<dyn WanAddrBinding>,
    pub session: Option<LinkStateHandle>,
}

pub async fn run(
    config: DhcpV4ClientServiceRuntimeConfig,
    services: DhcpV4ClientServices,
    service_status: ServiceHandle,
) {
    driver::run(config, services, service_status).await
}
