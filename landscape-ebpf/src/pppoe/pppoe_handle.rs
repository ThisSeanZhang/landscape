use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::{
    bpf_error::LdEbpfResult,
    bpf_rs_shared::pppoe_skb_fallback_skel,
    chain::tc_manager::{StageEntry, StageType},
    chain::xdp_manager::SkbPending,
    landscape::{OwnedOpenObject, pin_and_reuse_map},
    runtime::EbpfRuntime,
    stages::pppoe::XdpPppoeHandle,
};

mod tc_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_pppoe.skel.rs"));
}

pub use tc_pppoe_skel::types::pppoe_egress_tmpl as PppoeEgressTmpl;

/// Per-link terminal TC egress stage: the encap program lives at the
/// end of this link's WAN egress chain with the link's session
/// template baked into rodata, so it only touches packets that
/// traversed this chain (multi-link-per-iface safe once the chains
/// are chain-keyed).
struct TcPppoeStage {
    runtime: Arc<EbpfRuntime>,
    _skel: tc_pppoe_skel::TcPppoeSkel<'static>,
    _backing: OwnedOpenObject,
    link_chain_id: u16,
}

impl Drop for TcPppoeStage {
    fn drop(&mut self) {
        let _ = self.runtime.tc.remove(self.link_chain_id, StageType::Pppoe);
    }
}

pub struct PppoeHandle {
    runtime: Arc<EbpfRuntime>,
    _tc: TcPppoeStage,
    _xdp: XdpPppoeHandle,
    _ifindex: u32,
}

unsafe impl Send for PppoeHandle {}
unsafe impl Sync for PppoeHandle {}

impl Drop for PppoeHandle {
    fn drop(&mut self) {
        // Last native PPPoE link out detaches and forgets the shared
        // per-iface SKB fallback program.
        self.runtime.xdp.release_pppoe_skb_fallback(self._ifindex);
    }
}

pub fn create_pppoe_handle(
    rt: Arc<EbpfRuntime>,
    link_chain_id: u16,
    ifindex: u32,
    tmpl: PppoeEgressTmpl,
    _mtu: u16,
) -> LdEbpfResult<PppoeHandle> {
    let session_id = u16::from_be(tmpl.session_id);

    let tc = attach_tc_pppoe(&rt, link_chain_id, tmpl)?;
    let xdp = crate::stages::pppoe::init_xdp_pppoe(&rt, link_chain_id, session_id)?;
    rt.xdp.acquire_pppoe_skb_fallback(ifindex, prepare_pppoe_skb_pending)?;

    Ok(PppoeHandle {
        runtime: rt.clone(),
        _tc: tc,
        _xdp: xdp,
        _ifindex: ifindex,
    })
}

fn attach_tc_pppoe(
    rt: &Arc<EbpfRuntime>,
    link_chain_id: u16,
    tmpl: PppoeEgressTmpl,
) -> LdEbpfResult<TcPppoeStage> {
    let paths = &rt.paths;

    let builder = tc_pppoe_skel::TcPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "open tc_pppoe skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = tmpl;

    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_ingress,
        &paths.tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_egress,
        &paths.tc_pipe_exits_wan_egress_path(),
    )?;

    let skel = crate::bpf_ctx!(open_skel.load(), "load tc_pppoe skeleton")?;

    // Egress-only terminal stage: the empty ingress fds keep it out of
    // the WAN ingress chain (decap happens at the intro dispatch).
    let entry = StageEntry {
        wan_ingress_prog_v4_fd: 0,
        wan_ingress_prog_v6_fd: 0,
        wan_egress_prog_v4_fd: skel.progs.tc_pppoe_wan_egress_v4.as_fd().as_raw_fd(),
        wan_egress_prog_v6_fd: skel.progs.tc_pppoe_wan_egress_v6.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };

    rt.tc.inject(link_chain_id, StageType::Pppoe, entry)?;

    Ok(TcPppoeStage {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        link_chain_id,
    })
}

/// The shared per-iface SKB fallback decap program.  One instance serves
/// every native PPPoE link on the interface, so the session filter is
/// wildcarded (`session_id = 0` matches all sessions in the BPF program).
fn prepare_pppoe_skb_pending() -> LdEbpfResult<SkbPending> {
    let builder = pppoe_skb_fallback_skel::PppoeSkbFallbackSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "open pppoe_skb_fallback skeleton")?;
    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.session_id = 0;
    }
    let skel = crate::bpf_ctx!(open_skel.load(), "load pppoe_skb_fallback skeleton")?;

    Ok(SkbPending::new(backing, skel))
}
