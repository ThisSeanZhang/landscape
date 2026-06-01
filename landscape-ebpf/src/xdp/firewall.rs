use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::xdp::manager::{
    xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
    xdp_pipe_root_progs_path, StageType, XdpChainManager,
};
use crate::MAP_PATHS;

pub(crate) mod xdp_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_firewall.skel.rs"));
}

use xdp_firewall_skel::XdpFirewallSkelBuilder;

pub struct XdpFirewallHandle {
    _skel: xdp_firewall_skel::XdpFirewallSkel<'static>,
    _backing: OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpFirewallHandle {}
unsafe impl Sync for XdpFirewallHandle {}

impl Drop for XdpFirewallHandle {
    fn drop(&mut self) {
        let manager = XdpChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Firewall);
    }
}

pub fn init_xdp_firewall(ifindex: u32) -> LdEbpfResult<XdpFirewallHandle> {
    let builder = XdpFirewallSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_firewall skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path(),),
        "xdp_firewall pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path(),),
        "xdp_firewall pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path(),),
        "xdp_firewall pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_firewall pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.firewall_block_ip4_map,
            &MAP_PATHS.firewall_ipv4_block,
        ),
        "xdp_firewall pin firewall_block_ip4_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.firewall_block_ip6_map,
            &MAP_PATHS.firewall_ipv6_block,
        ),
        "xdp_firewall pin firewall_block_ip6_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.firewall_conn_metric_events,
            &MAP_PATHS.firewall_conn_metric_events,
        ),
        "xdp_firewall pin firewall_conn_metric_events"
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load xdp_firewall skeleton")?;

    let lan_fd = skel.progs.xdp_firewall_lan.as_fd().as_raw_fd();
    let wan_fd = skel.progs.xdp_firewall_wan.as_fd().as_raw_fd();
    let next_fd = skel.maps.next_stage.as_fd().as_raw_fd();

    let manager = XdpChainManager::instance();
    manager.inject(ifindex, StageType::Firewall, lan_fd, wan_fd, next_fd)?;

    Ok(XdpFirewallHandle { _skel: skel, _backing: backing, ifindex })
}
