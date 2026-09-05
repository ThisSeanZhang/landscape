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
    ifindex: u32,
}

impl Drop for TcMssHandle {
    fn drop(&mut self) {
        use crate::chain::tc_manager::StageType;
        let _ = self.runtime.tc.remove(self.ifindex, StageType::Mss);
    }
}

pub fn attach_tc_mss(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    mtu: u16,
    has_mac: bool,
) -> LdEbpfResult<TcMssHandle> {
    use crate::chain::tc_manager::{StageEntry, StageType};
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = &rt.paths;
    rt.tc.ensure_roots(ifindex, has_mac)?;

    let builder = tc_mss_skel::TcMssSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_mss skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().mtu_size = mtu;
    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset =
        if has_mac { 14 } else { 0 };

    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_ingress,
        &paths.tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_egress,
        &paths.tc_pipe_exits_wan_egress_path(),
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_mss skeleton")?;

    let entry = StageEntry {
        wan_ingress_prog_fd: skel.progs.tc_mss_wan_ingress.as_fd().as_raw_fd(),
        wan_egress_prog_fd: skel.progs.tc_mss_wan_egress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };

    rt.tc.inject(ifindex, StageType::Mss, entry)?;

    Ok(TcMssHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        ifindex,
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
    ifindex: u32,
}

unsafe impl Send for XdpMssHandle {}
unsafe impl Sync for XdpMssHandle {}

impl Drop for XdpMssHandle {
    fn drop(&mut self) {
        use crate::chain::xdp_manager::StageType;
        let _ = self.runtime.xdp.remove(self.ifindex, StageType::Mss);
    }
}

pub fn init_xdp_mss(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    mtu_size: u16,
) -> LdEbpfResult<XdpMssHandle> {
    use crate::chain::xdp_manager::StageType;
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
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

    let lan_fd = skel.progs.xdp_mss_lan.as_fd().as_raw_fd();
    let wan_fd = skel.progs.xdp_mss_wan.as_fd().as_raw_fd();
    let next_fd = skel.maps.next_stage.as_fd().as_raw_fd();

    rt.xdp.inject(ifindex, StageType::Mss, lan_fd, wan_fd, next_fd)?;

    Ok(XdpMssHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        ifindex,
    })
}

// ========================================================================
// Mode-aware unified entry (TC ingress+egress + XDP LAN+WAN)
// ========================================================================

pub fn init_mss(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    mtu: u16,
    has_mac: bool,
) -> LdEbpfResult<MssHandle> {
    Ok(MssHandle {
        tc: Some(attach_tc_mss(rt, ifindex, mtu, has_mac)?),
        xdp: Some(init_xdp_mss(rt, ifindex, mtu)?),
    })
}
