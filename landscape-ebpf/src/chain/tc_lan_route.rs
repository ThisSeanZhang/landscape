use libbpf_rs::TcAttachPoint;

use crate::bpf_error::LdEbpfResult;
use crate::chain::tc_manager::TcChainManager;
use crate::landscape::TcHookProxy;
use crate::LAN_ROUTE_INGRESS_PRIORITY;

pub struct TcLanRouteHandle {
    ingress_hook: Option<TcHookProxy>,
    ifindex: u32,
}

unsafe impl Send for TcLanRouteHandle {}
unsafe impl Sync for TcLanRouteHandle {}

impl Drop for TcLanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
        TcChainManager::instance().remove_roots(self.ifindex);
    }
}

pub fn init_tc_lan_route(ifindex: u32) -> LdEbpfResult<TcLanRouteHandle> {
    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex)?;

    let mut ingress_hook = TcHookProxy::new(
        manager.tc_lan_ingress_intro_prog(),
        ifindex as i32,
        TcAttachPoint::Ingress,
        LAN_ROUTE_INGRESS_PRIORITY,
    );
    ingress_hook.attach();

    Ok(TcLanRouteHandle { ingress_hook: Some(ingress_hook), ifindex })
}
