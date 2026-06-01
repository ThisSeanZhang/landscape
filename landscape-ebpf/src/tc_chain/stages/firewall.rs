use std::os::fd::{AsFd, AsRawFd};

use libbpf_rs::skel::{OpenSkel, SkelBuilder};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::tc_chain::manager::{
    tc_pipe_exits_lan_ingress_path, tc_pipe_exits_wan_egress_path, tc_pipe_exits_wan_ingress_path,
    StageEntry, StageType, TcChainManager,
};
use crate::MAP_PATHS;

mod tc_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_firewall.skel.rs"));
}

pub struct TcFirewallHandle {
    _skel: tc_firewall_skel::TcFirewallSkel<'static>,
    _backing: OwnedOpenObject,
    ifindex: u32,
}

impl Drop for TcFirewallHandle {
    fn drop(&mut self) {
        let manager = TcChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Firewall);
    }
}

pub fn attach_tc_firewall(ifindex: u32, has_mac: bool) -> LdEbpfResult<TcFirewallHandle> {
    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex)?;

    let builder = tc_firewall_skel::TcFirewallSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_firewall skeleton")?;

    open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset =
        if has_mac { 14 } else { 0 };

    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_ingress,
        &tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_egress,
        &tc_pipe_exits_wan_egress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_lan_ingress,
        &tc_pipe_exits_lan_ingress_path(),
    )?;

    pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip4_map, &MAP_PATHS.firewall_ipv4_block)?;
    pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip6_map, &MAP_PATHS.firewall_ipv6_block)?;
    pin_and_reuse_map(
        &mut open_skel.maps.firewall_conn_metric_events,
        &MAP_PATHS.firewall_conn_metric_events,
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_firewall skeleton")?;

    let entry = StageEntry {
        wan_ingress_prog_fd: skel.progs.tc_firewall_wan_ingress.as_fd().as_raw_fd(),
        wan_egress_prog_fd: skel.progs.tc_firewall_wan_egress.as_fd().as_raw_fd(),
        lan_ingress_prog_fd: skel.progs.tc_firewall_lan_ingress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        lan_ingress_next_stage_fd: skel.maps.lan_ingress_next_stage.as_fd().as_raw_fd(),
    };

    manager.inject(ifindex, StageType::Firewall, entry)?;

    Ok(TcFirewallHandle { _skel: skel, _backing: backing, ifindex })
}
