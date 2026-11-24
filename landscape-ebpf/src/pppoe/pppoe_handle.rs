use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::{
    bpf_error::LdEbpfResult,
    chain::stage::{FamilyProg, FromLanStageType, StageFamily},
    chain::wan_link::WanLinkDataplane,
    landscape::OwnedOpenObject,
    stages::pppoe::XdpPppoeHandle,
};

pub use crate::skel::tc_pppoe::types::pppoe_egress_tmpl as PppoeEgressTmpl;

/// Per-link terminal TC egress stage: the encap program lives at the
/// end of this link's WAN egress chain with the link's session
/// template baked into rodata, so it only touches packets that
/// traversed this chain (multi-link-per-iface safe once the chains
/// are chain-keyed).
struct TcPppoeStage {
    dp: Arc<WanLinkDataplane>,
    _skel: crate::skel::tc_pppoe::TcPppoeSkel<'static>,
    _backing: OwnedOpenObject,
}

impl Drop for TcPppoeStage {
    fn drop(&mut self) {
        for family in StageFamily::ALL {
            self.dp.tc().remove_from_lan(FromLanStageType::Pppoe, family);
        }
    }
}

pub struct PppoeHandle {
    _tc: TcPppoeStage,
    _xdp: XdpPppoeHandle,
}

unsafe impl Send for PppoeHandle {}
unsafe impl Sync for PppoeHandle {}

pub fn create_pppoe_handle(
    dp: Arc<WanLinkDataplane>,
    _ifindex: u32,
    tmpl: PppoeEgressTmpl,
    _mtu: u16,
) -> LdEbpfResult<PppoeHandle> {
    let session_id = u16::from_be(tmpl.session_id);

    let tc = attach_tc_pppoe(&dp, tmpl)?;
    let xdp = crate::stages::pppoe::init_xdp_pppoe(&dp, session_id)?;
    Ok(PppoeHandle { _tc: tc, _xdp: xdp })
}

fn attach_tc_pppoe(
    dp: &Arc<WanLinkDataplane>,
    tmpl: PppoeEgressTmpl,
) -> LdEbpfResult<TcPppoeStage> {
    let builder = crate::skel::tc_pppoe::TcPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = crate::bpf_ctx!(builder.open(obj), "open tc_pppoe skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = tmpl;

    dp.reuse_tc_wan_egress_exit_map(&mut open_skel.maps.tc_from_lan_exit_map)?;

    let skel = crate::bpf_ctx!(open_skel.load(), "load tc_pppoe skeleton")?;

    // Egress-only terminal stage (decap happens at the intro dispatch).
    let next_egress_fd = skel.maps.wan_egress_next_stage.as_fd().as_raw_fd();
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.tc_pppoe_wan_egress_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.tc_pppoe_wan_egress_v6.as_fd().as_raw_fd()),
    ] {
        dp.tc().inject_from_lan(
            FromLanStageType::Pppoe,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_egress_fd },
        )?;
    }

    Ok(TcPppoeStage { dp: dp.clone(), _skel: skel, _backing: backing })
}
