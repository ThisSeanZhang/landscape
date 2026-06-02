use landscape_common::args::RouteMode;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;

// ========================================================================
// TC firewall
// ========================================================================

mod tc_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_firewall.skel.rs"));
}

/// Result of loading both TC and XDP firewall for one interface.
pub struct FirewallHandle {
    pub tc: Option<TcFirewallHandle>,
    pub xdp: Option<XdpFirewallHandle>,
}

pub struct TcFirewallHandle {
    _skel: tc_firewall_skel::TcFirewallSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

impl Drop for TcFirewallHandle {
    fn drop(&mut self) {
        use crate::chain::tc_manager::{StageType, TcChainManager};
        let manager = TcChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Firewall);
    }
}

pub fn attach_tc_firewall(ifindex: u32, has_mac: bool) -> LdEbpfResult<TcFirewallHandle> {
    use crate::chain::tc_manager::{
        tc_pipe_exits_lan_ingress_path, tc_pipe_exits_wan_egress_path,
        tc_pipe_exits_wan_ingress_path, StageEntry, StageType, TcChainManager,
    };
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use crate::MAP_PATHS;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

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

// ========================================================================
// XDP firewall
// ========================================================================

pub(crate) mod xdp_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_firewall.skel.rs"));
}

pub struct XdpFirewallHandle {
    _skel: xdp_firewall_skel::XdpFirewallSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpFirewallHandle {}
unsafe impl Sync for XdpFirewallHandle {}

impl Drop for XdpFirewallHandle {
    fn drop(&mut self) {
        use crate::chain::xdp_manager::{StageType, XdpChainManager};
        let manager = XdpChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Firewall);
    }
}

pub fn init_xdp_firewall(ifindex: u32) -> LdEbpfResult<XdpFirewallHandle> {
    use crate::chain::xdp_manager::{
        xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
        xdp_pipe_root_progs_path, StageType, XdpChainManager,
    };
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use crate::MAP_PATHS;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    use xdp_firewall_skel::XdpFirewallSkelBuilder;

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

// ========================================================================
// TC firewall — egress only (used by XDP mode for local outbound traffic)
// ========================================================================

pub fn attach_tc_firewall_egress(ifindex: u32, has_mac: bool) -> LdEbpfResult<TcFirewallHandle> {
    use crate::chain::tc_manager::{
        tc_pipe_exits_lan_ingress_path, tc_pipe_exits_wan_egress_path,
        tc_pipe_exits_wan_ingress_path, StageEntry, StageType, TcChainManager,
    };
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use crate::MAP_PATHS;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex)?;

    let builder = tc_firewall_skel::TcFirewallSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_firewall skeleton (egress)")?;

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

    let skel = bpf_ctx!(open_skel.load(), "load tc_firewall skeleton (egress)")?;

    let entry = StageEntry {
        wan_ingress_prog_fd: 0,
        wan_egress_prog_fd: skel.progs.tc_firewall_wan_egress.as_fd().as_raw_fd(),
        lan_ingress_prog_fd: 0,
        wan_ingress_next_stage_fd: 0,
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        lan_ingress_next_stage_fd: 0,
    };

    manager.inject(ifindex, StageType::Firewall, entry)?;

    Ok(TcFirewallHandle { _skel: skel, _backing: backing, ifindex })
}

// ========================================================================
// Mode-aware unified entry
// ========================================================================

pub fn init_firewall(mode: RouteMode, ifindex: u32, has_mac: bool) -> LdEbpfResult<FirewallHandle> {
    match mode {
        RouteMode::Tc => Ok(FirewallHandle {
            tc: Some(attach_tc_firewall(ifindex, has_mac)?),
            xdp: None,
        }),
        RouteMode::Xdp => Ok(FirewallHandle {
            tc: Some(attach_tc_firewall_egress(ifindex, has_mac)?),
            xdp: Some(init_xdp_firewall(ifindex)?),
        }),
    }
}
