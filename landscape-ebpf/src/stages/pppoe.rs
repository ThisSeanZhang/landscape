use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;

pub(crate) mod xdp_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_pppoe.skel.rs"));
}

pub struct XdpPppoeHandle {
    _skel: xdp_pppoe_skel::XdpPppoeSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpPppoeHandle {}
unsafe impl Sync for XdpPppoeHandle {}

impl Drop for XdpPppoeHandle {
    fn drop(&mut self) {
        use crate::chain::xdp_manager::{StageType, XdpChainManager};
        let manager = XdpChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Pppoe);
    }
}

pub fn init_xdp_pppoe(ifindex: u32, session_id: u16) -> LdEbpfResult<XdpPppoeHandle> {
    use crate::chain::xdp_manager::{
        xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
        xdp_pipe_root_progs_path, StageType, XdpChainManager,
    };
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    use xdp_pppoe_skel::XdpPppoeSkelBuilder;

    let builder = XdpPppoeSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_pppoe skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path()),
        "xdp_pppoe pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path()),
        "xdp_pppoe pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path()),
        "xdp_pppoe pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_pppoe pin xdp_lan_pipe_root_progs"
    )?;

    if let Some(rodata) = open_skel.maps.rodata_data.as_deref_mut() {
        rodata.session_id = session_id.to_be();
    }

    let skel = bpf_ctx!(open_skel.load(), "load xdp_pppoe skeleton")?;

    let lan_fd = skel.progs.xdp_pppoe_encap_lan.as_fd().as_raw_fd();
    let next_fd = skel.maps.next_stage.as_fd().as_raw_fd();

    let manager = XdpChainManager::instance();
    manager.inject(ifindex, StageType::Pppoe, lan_fd, 0, next_fd)?;

    Ok(XdpPppoeHandle { _skel: skel, _backing: backing, ifindex })
}
