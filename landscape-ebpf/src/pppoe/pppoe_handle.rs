use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS,
};

use crate::{
    bpf_error::LdEbpfResult,
    bpf_rs_shared::xdp_skb_pppoe_skel,
    chain::xdp_manager::{SkbPending, XdpChainManager},
    landscape::{OwnedOpenObject, TcHookProxy},
    stages::pppoe::XdpPppoeHandle,
    PPPOE_EGRESS_PRIORITY,
};

mod tc_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_pppoe.skel.rs"));
}

pub use tc_pppoe_skel::types::pppoe_egress_tmpl as PppoeEgressTmpl;

struct StandalonePppoe {
    _skel: tc_pppoe_skel::TcPppoeSkel<'static>,
    _backing: OwnedOpenObject,
    _hook: TcHookProxy,
}

pub struct PppoeHandle {
    _tc: StandalonePppoe,
    _xdp: XdpPppoeHandle,
    _ifindex: u32,
}

unsafe impl Send for PppoeHandle {}
unsafe impl Sync for PppoeHandle {}

impl Drop for PppoeHandle {
    fn drop(&mut self) {
        let _ = XdpChainManager::instance().take_skb_pending(self._ifindex);
        let _ = XdpChainManager::instance().take_skb_bundle(self._ifindex);
    }
}

pub fn create_pppoe_handle(
    ifindex: u32,
    tmpl: PppoeEgressTmpl,
    _mtu: u16,
) -> LdEbpfResult<PppoeHandle> {
    let session_id = u16::from_be(tmpl.session_id);

    let tc = attach_standalone_pppoe(ifindex, tmpl)?;
    let xdp = crate::stages::pppoe::init_xdp_pppoe(ifindex, session_id)?;
    let pending = prepare_pppoe_skb_pending(ifindex, session_id)?;
    XdpChainManager::instance().set_skb_pending(ifindex, pending);

    Ok(PppoeHandle { _tc: tc, _xdp: xdp, _ifindex: ifindex })
}

fn attach_standalone_pppoe(ifindex: u32, tmpl: PppoeEgressTmpl) -> LdEbpfResult<StandalonePppoe> {
    let builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "open tc_pppoe skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = tmpl;

    let skel = crate::bpf_ctx!(open_skel.load(), "load tc_pppoe skeleton")?;

    let mut hook = TcHookProxy::new(
        &skel.progs.tc_pppoe_wan_egress,
        ifindex as i32,
        TC_EGRESS,
        PPPOE_EGRESS_PRIORITY,
    );
    hook.attach();

    Ok(StandalonePppoe { _skel: skel, _backing: backing, _hook: hook })
}

fn prepare_pppoe_skb_pending(_ifindex: u32, session_id: u16) -> LdEbpfResult<SkbPending> {
    let builder = xdp_skb_pppoe_skel::XdpSkbPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "open xdp_skb_pppoe skeleton")?;
    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.session_id = session_id.to_be();
    }
    let skel = crate::bpf_ctx!(open_skel.load(), "load xdp_skb_pppoe skeleton")?;

    Ok(SkbPending::new(backing, skel))
}
