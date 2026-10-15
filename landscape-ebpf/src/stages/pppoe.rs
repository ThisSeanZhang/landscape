use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::wan_link::WanLinkDataplane;

pub(crate) mod xdp_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_pppoe.skel.rs"));
}

pub struct XdpPppoeHandle {
    dp: Arc<WanLinkDataplane>,
    _skel: xdp_pppoe_skel::XdpPppoeSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
}

unsafe impl Send for XdpPppoeHandle {}
unsafe impl Sync for XdpPppoeHandle {}

impl Drop for XdpPppoeHandle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, StageFamily};
        for family in StageFamily::ALL {
            self.dp.xdp().remove_from_lan(FromLanStageType::Pppoe, family);
        }
    }
}

pub fn init_xdp_pppoe(dp: &Arc<WanLinkDataplane>, session_id: u16) -> LdEbpfResult<XdpPppoeHandle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    use xdp_pppoe_skel::XdpPppoeSkelBuilder;

    let paths = dp.backbone().paths();
    let builder = XdpPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_pppoe skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path()
        ),
        "xdp_pppoe pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path()),
        "xdp_pppoe pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path()),
        "xdp_pppoe pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_pppoe pin xdp_lan_pipe_root_progs"
    )?;

    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.session_id = session_id.to_be();
    }

    let skel = bpf_ctx!(open_skel.load(), "load xdp_pppoe skeleton")?;

    // PPPoE encap is family-agnostic (one body, two entry programs) and
    // LAN-side only.
    let next_stage_fd = skel.maps.next_stage.as_fd().as_raw_fd();
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.xdp_pppoe_encap_lan_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.xdp_pppoe_encap_lan_v6.as_fd().as_raw_fd()),
    ] {
        dp.xdp().inject_from_lan(
            FromLanStageType::Pppoe,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_stage_fd },
        )?;
    }

    Ok(XdpPppoeHandle { dp: dp.clone(), _skel: skel, _backing: backing })
}
