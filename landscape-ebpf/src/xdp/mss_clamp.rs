use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::xdp::manager::{
    xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
    xdp_pipe_root_progs_path, StageType, XdpChainManager,
};

pub(crate) mod xdp_mss_clamp_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_mss_clamp.skel.rs"));
}

use xdp_mss_clamp_skel::XdpMssClampSkelBuilder;

pub struct XdpMssClampHandle {
    _skel: xdp_mss_clamp_skel::XdpMssClampSkel<'static>,
    _backing: OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpMssClampHandle {}
unsafe impl Sync for XdpMssClampHandle {}

impl Drop for XdpMssClampHandle {
    fn drop(&mut self) {
        let manager = XdpChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Mss);
    }
}

pub fn init_xdp_mss_clamp(ifindex: u32, mtu_size: u16) -> LdEbpfResult<XdpMssClampHandle> {
    let builder = XdpMssClampSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_mss_clamp skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path(),),
        "xdp_mss_clamp pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path(),),
        "xdp_mss_clamp pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path(),),
        "xdp_mss_clamp pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_mss_clamp pin xdp_lan_pipe_root_progs"
    )?;

    {
        let rodata = open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .expect("xdp_mss_clamp rodata not memory mapped");
        rodata.mtu_size = mtu_size;
    }

    let skel = bpf_ctx!(open_skel.load(), "load xdp_mss_clamp skeleton")?;

    let lan_fd = skel.progs.xdp_mss_clamp_lan.as_fd().as_raw_fd();
    let wan_fd = skel.progs.xdp_mss_clamp_wan.as_fd().as_raw_fd();
    let next_fd = skel.maps.next_stage.as_fd().as_raw_fd();

    let manager = XdpChainManager::instance();
    manager.inject(ifindex, StageType::Mss, lan_fd, wan_fd, next_fd)?;

    Ok(XdpMssClampHandle { _skel: skel, _backing: backing, ifindex })
}
