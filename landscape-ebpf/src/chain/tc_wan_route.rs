use libbpf_rs::TcAttachPoint;

use crate::bpf_error::LdEbpfResult;
use crate::chain::tc_manager::TcChainManager;
use crate::landscape::TcHookProxy;

use crate::{WAN_ROUTE_EGRESS_PRIORITY, WAN_ROUTE_INGRESS_PRIORITY};

pub struct TcWanRouteHandle {
    ingress_hook: Option<TcHookProxy>,
    egress_hook: Option<TcHookProxy>,
    ifindex: u32,
}

unsafe impl Send for TcWanRouteHandle {}
unsafe impl Sync for TcWanRouteHandle {}

impl Drop for TcWanRouteHandle {
    fn drop(&mut self) {
        self.ingress_hook.take();
        self.egress_hook.take();
        TcChainManager::instance().remove_roots(self.ifindex);
    }
}

pub fn init_tc_wan_route(ifindex: u32) -> LdEbpfResult<TcWanRouteHandle> {
    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex)?;

    let mut ingress_hook = TcHookProxy::new(
        manager.tc_wan_intro_prog(),
        ifindex as i32,
        TcAttachPoint::Ingress,
        WAN_ROUTE_INGRESS_PRIORITY,
    );
    ingress_hook.attach();

    let mut egress_hook = TcHookProxy::new(
        manager.tc_wan_egress_intro_prog(),
        ifindex as i32,
        TcAttachPoint::Egress,
        WAN_ROUTE_EGRESS_PRIORITY,
    );
    egress_hook.attach();

    Ok(TcWanRouteHandle {
        ingress_hook: Some(ingress_hook),
        egress_hook: Some(egress_hook),
        ifindex,
    })
}
