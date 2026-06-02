use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::tc_manager::{
    tc_lan_ingress_roots_path, tc_pipe_exits_lan_ingress_path, TcChainManager,
};
use crate::landscape::{OwnedOpenObject, TcHookProxy};
use crate::LAN_ROUTE_INGRESS_PRIORITY;

mod tc_lan_ingress_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_chain.skel.rs"));
}
use tc_lan_ingress_chain_skel::{TcLanIngressChainSkel, TcLanIngressChainSkelBuilder};

pub struct TcLanRouteHandle {
    _intro_skel: TcLanIngressChainSkel<'static>,
    _intro_backing: OwnedOpenObject,
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

pub fn init_tc_lan_route(ifindex: u32, has_mac: bool) -> LdEbpfResult<TcLanRouteHandle> {
    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex)?;

    let l3_offset: u32 = if has_mac { 14 } else { 0 };

    let (intro_backing, obj) = OwnedOpenObject::new();
    let builder = TcLanIngressChainSkelBuilder::default();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open per-if tc_lan_ingress_chain")?;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
    crate::map_setting::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.tc_lan_ingress_roots,
        &tc_lan_ingress_roots_path(),
    );
    crate::map_setting::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.tc_pipe_exits_lan_ingress,
        &tc_pipe_exits_lan_ingress_path(),
    );
    let intro_skel = bpf_ctx!(open_skel.load(), "load per-if tc_lan_ingress_chain")?;
    let mut ingress_hook = TcHookProxy::new(
        &intro_skel.progs.tc_lan_ingress_intro,
        ifindex as i32,
        libbpf_rs::TC_INGRESS,
        LAN_ROUTE_INGRESS_PRIORITY,
    );
    ingress_hook.attach();

    Ok(TcLanRouteHandle {
        _intro_skel: intro_skel,
        _intro_backing: intro_backing,
        ingress_hook: Some(ingress_hook),
        ifindex,
    })
}
