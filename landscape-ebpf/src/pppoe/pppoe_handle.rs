use std::sync::Arc;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    TC_EGRESS,
};

use crate::{
    bpf_error::LdEbpfResult,
    bpf_rs_shared::xdp_skb_pppoe_skel,
    chain::hub::{ChainHub, SkbPending},
    landscape::{OwnedOpenObject, TcHookProxy},
    runtime::EbpfRuntime,
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
    hub: Arc<ChainHub>,
    _tc: StandalonePppoe,
    _xdp: XdpPppoeHandle,
    _ifindex: u32,
}

unsafe impl Send for PppoeHandle {}
unsafe impl Sync for PppoeHandle {}

impl Drop for PppoeHandle {
    fn drop(&mut self) {
        // Only the last session on this attach iface tears the shared,
        // map-driven stripper down.
        if self.hub.release_skb_stripper(self._ifindex) {
            let _ = self.hub.take_skb_pending(self._ifindex);
            let _ = self.hub.take_skb_bundle(self._ifindex);
        }
    }
}

pub fn create_pppoe_handle(
    rt: Arc<EbpfRuntime>,
    ifindex: u32,
    link_chain_id: u16,
    tmpl: PppoeEgressTmpl,
    _mtu: u16,
) -> LdEbpfResult<PppoeHandle> {
    let session_id = u16::from_be(tmpl.session_id);

    let tc = attach_standalone_pppoe(ifindex, tmpl)?;
    let xdp = crate::stages::pppoe::init_xdp_pppoe(&rt, ifindex, link_chain_id, session_id)?;
    // The stripper is dispatch-map driven: one instance per attach iface
    // serves every session, so only the first session prepares it.
    if rt.hub.retain_skb_stripper(ifindex) {
        match prepare_pppoe_skb_pending(&rt) {
            Ok(pending) => rt.hub.set_skb_pending(ifindex, pending),
            Err(e) => {
                // Abandon ownership so a later session can retry; the IP
                // selector fallback keeps traffic working without the stripper.
                rt.hub.forget_skb_stripper(ifindex);
                tracing::warn!(
                    "prepare SKB PPPoE stripper for ifindex={ifindex} failed: {e}; \
                     sessions fall back to IP dispatch"
                );
                return Err(e);
            }
        }
    }

    Ok(PppoeHandle {
        hub: rt.hub.clone(),
        _tc: tc,
        _xdp: xdp,
        _ifindex: ifindex,
    })
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

fn prepare_pppoe_skb_pending(rt: &Arc<EbpfRuntime>) -> LdEbpfResult<SkbPending> {
    let paths = rt.paths.as_ref();
    let builder = xdp_skb_pppoe_skel::XdpSkbPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "open xdp_skb_pppoe skeleton")?;

    // Share the WAN intro dispatch map: session add/remove is a runtime map
    // update (register/remove_ppp_session_selector), so a single stripper
    // instance per attach iface serves every session on it.
    crate::maps::reuse_pinned_map_or_recreate(
        &mut open_skel.maps.wan_intro_dispatch_map,
        &paths.xdp_wan_intro_dispatch_path(),
    );

    let skel = crate::bpf_ctx!(open_skel.load(), "load xdp_skb_pppoe skeleton")?;

    Ok(SkbPending::new(backing, skel))
}
