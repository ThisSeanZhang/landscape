use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::link_chain::{LinkChain, StageType};
use crate::maps::wan::{register_ppp_session_selector, remove_ppp_session_selector};
use crate::runtime::EbpfRuntime;

pub(crate) mod xdp_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_pppoe.skel.rs"));
}

pub struct XdpPppoeHandle {
    chain: Arc<LinkChain>,
    _skel: xdp_pppoe_skel::XdpPppoeSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    paths: crate::LandscapeMapPath,
    link_chain_id: u16,
    session_id: u16,
}

unsafe impl Send for XdpPppoeHandle {}
unsafe impl Sync for XdpPppoeHandle {}

impl Drop for XdpPppoeHandle {
    fn drop(&mut self) {
        let _ = self.chain.remove_xdp(StageType::Pppoe);
        remove_ppp_session_selector(&self.paths, self.link_chain_id, self.session_id);
    }
}

pub fn init_xdp_pppoe(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    link_chain_id: u16,
    session_id: u16,
) -> LdEbpfResult<XdpPppoeHandle> {
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    use xdp_pppoe_skel::XdpPppoeSkelBuilder;

    let paths = rt.paths.as_ref();
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

    let lan_fd = skel.progs.xdp_pppoe_encap_lan.as_fd().as_raw_fd();
    let next_fd = skel.maps.next_stage.as_fd().as_raw_fd();

    let chain = rt.hub.get_or_create_chain(link_chain_id, ifindex)?;
    chain.inject_xdp(StageType::Pppoe, lan_fd, 0, next_fd)?;

    register_ppp_session_selector(paths, link_chain_id, session_id);

    Ok(XdpPppoeHandle {
        chain,
        _skel: skel,
        _backing: backing,
        paths: paths.clone(),
        link_chain_id,
        session_id,
    })
}
