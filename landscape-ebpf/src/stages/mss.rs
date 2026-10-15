use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::runtime::EbpfRuntime;

// ========================================================================
// TC MSS clamp
// ========================================================================

pub(crate) mod tc_mss_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_mss.skel.rs"));
}

pub struct MssHandle {
    pub tc: Option<TcMssHandle>,
    pub xdp: Option<XdpMssHandle>,
}

pub struct TcMssHandle {
    runtime: Arc<EbpfRuntime>,
    _skel: tc_mss_skel::TcMssSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    link_chain_id: u16,
}

impl Drop for TcMssHandle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        for family in StageFamily::ALL {
            let _ =
                self.runtime.tc.remove_from_wan(self.link_chain_id, FromWanStageType::Mss, family);
            let _ =
                self.runtime.tc.remove_from_lan(self.link_chain_id, FromLanStageType::Mss, family);
        }
    }
}

pub fn attach_tc_mss(
    rt: &Arc<EbpfRuntime>,
    link_chain_id: u16,
    mtu: u16,
    has_eth_header: bool,
) -> LdEbpfResult<TcMssHandle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, FromWanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = &rt.paths;

    let builder = tc_mss_skel::TcMssSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_mss skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().mtu_size = mtu;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset =
        if has_eth_header { 14 } else { 0 };

    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_ingress,
        &paths.tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_egress,
        &paths.tc_pipe_exits_wan_egress_path(),
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_mss skeleton")?;

    let next_ingress_fd = skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd();
    let next_egress_fd = skel.maps.wan_egress_next_stage.as_fd().as_raw_fd();
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.tc_mss_wan_ingress_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.tc_mss_wan_ingress_v6.as_fd().as_raw_fd()),
    ] {
        rt.tc.inject_from_wan(
            link_chain_id,
            FromWanStageType::Mss,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_ingress_fd },
        )?;
    }
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.tc_mss_wan_egress_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.tc_mss_wan_egress_v6.as_fd().as_raw_fd()),
    ] {
        rt.tc.inject_from_lan(
            link_chain_id,
            FromLanStageType::Mss,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_egress_fd },
        )?;
    }

    Ok(TcMssHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        link_chain_id,
    })
}

// ========================================================================
// XDP MSS clamp
// ========================================================================

pub(crate) mod xdp_mss_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_mss.skel.rs"));
}

pub struct XdpMssHandle {
    runtime: Arc<EbpfRuntime>,
    _skel: xdp_mss_skel::XdpMssSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    link_chain_id: u16,
}

unsafe impl Send for XdpMssHandle {}
unsafe impl Sync for XdpMssHandle {}

impl Drop for XdpMssHandle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        for family in StageFamily::ALL {
            let _ =
                self.runtime.xdp.remove_from_wan(self.link_chain_id, FromWanStageType::Mss, family);
            let _ =
                self.runtime.xdp.remove_from_lan(self.link_chain_id, FromLanStageType::Mss, family);
        }
    }
}

pub fn init_xdp_mss(
    rt: &Arc<EbpfRuntime>,
    link_chain_id: u16,
    mtu_size: u16,
) -> LdEbpfResult<XdpMssHandle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, FromWanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    use xdp_mss_skel::XdpMssSkelBuilder;

    let paths = &rt.paths;
    let builder = XdpMssSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_mss skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path(),
        ),
        "xdp_mss pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path(),),
        "xdp_mss pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path(),),
        "xdp_mss pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_mss pin xdp_lan_pipe_root_progs"
    )?;

    {
        let rodata =
            open_skel.maps.rodata_data.as_deref_mut().expect("xdp_mss rodata not memory mapped");
        rodata.mtu_size = mtu_size;
    }

    let skel = bpf_ctx!(open_skel.load(), "load xdp_mss skeleton")?;

    let next_stage_fd = skel.maps.next_stage.as_fd().as_raw_fd();
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.xdp_mss_wan_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.xdp_mss_wan_v6.as_fd().as_raw_fd()),
    ] {
        rt.xdp.inject_from_wan(
            link_chain_id,
            FromWanStageType::Mss,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_stage_fd },
        )?;
    }
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.xdp_mss_lan_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.xdp_mss_lan_v6.as_fd().as_raw_fd()),
    ] {
        rt.xdp.inject_from_lan(
            link_chain_id,
            FromLanStageType::Mss,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_stage_fd },
        )?;
    }

    Ok(XdpMssHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        link_chain_id,
    })
}

// ========================================================================
// Mode-aware unified entry (TC ingress+egress + XDP LAN+WAN)
// ========================================================================

pub fn init_mss(
    rt: &Arc<EbpfRuntime>,
    link_chain_id: u16,
    mtu: u16,
    has_eth_header: bool,
) -> LdEbpfResult<MssHandle> {
    Ok(MssHandle {
        tc: Some(attach_tc_mss(rt, link_chain_id, mtu, has_eth_header)?),
        xdp: Some(init_xdp_mss(rt, link_chain_id, mtu)?),
    })
}
