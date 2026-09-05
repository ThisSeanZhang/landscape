use std::sync::Arc;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::runtime::EbpfRuntime;

// ========================================================================
// TC firewall
// ========================================================================

pub(crate) mod tc_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_firewall.skel.rs"));
}

/// Result of loading both TC and XDP firewall for one interface.
pub struct FirewallHandle {
    pub tc: Option<TcFirewallHandle>,
    pub xdp: Option<XdpFirewallHandle>,
}

pub struct TcFirewallHandle {
    runtime: Arc<EbpfRuntime>,
    _skel: tc_firewall_skel::TcFirewallSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

impl Drop for TcFirewallHandle {
    fn drop(&mut self) {
        use crate::chain::tc_manager::StageType;
        let _ = self.runtime.tc.remove(self.ifindex, StageType::Firewall);
    }
}

pub fn attach_tc_firewall(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    has_mac: bool,
) -> LdEbpfResult<TcFirewallHandle> {
    use crate::chain::tc_manager::{StageEntry, StageType};
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = &rt.paths;
    rt.tc.ensure_roots(ifindex, has_mac)?;

    let builder = tc_firewall_skel::TcFirewallSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_firewall skeleton")?;

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

    pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip4_map, &paths.firewall_ipv4_block)?;
    pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip6_map, &paths.firewall_ipv6_block)?;
    pin_and_reuse_map(
        &mut open_skel.maps.firewall_conn_metric_events,
        &paths.firewall_conn_metric_events,
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_firewall skeleton")?;

    let entry = StageEntry {
        wan_ingress_prog_fd: skel.progs.tc_firewall_wan_ingress.as_fd().as_raw_fd(),
        wan_egress_prog_fd: skel.progs.tc_firewall_wan_egress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };

    rt.tc.inject(ifindex, StageType::Firewall, entry)?;

    Ok(TcFirewallHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        ifindex,
    })
}

// ========================================================================
// XDP firewall
// ========================================================================

pub(crate) mod xdp_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_firewall.skel.rs"));
}

pub struct XdpFirewallHandle {
    runtime: Arc<EbpfRuntime>,
    _skel: xdp_firewall_skel::XdpFirewallSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpFirewallHandle {}
unsafe impl Sync for XdpFirewallHandle {}

impl Drop for XdpFirewallHandle {
    fn drop(&mut self) {
        use crate::chain::xdp_manager::StageType;
        let _ = self.runtime.xdp.remove(self.ifindex, StageType::Firewall);
    }
}

pub fn init_xdp_firewall(rt: &Arc<EbpfRuntime>, ifindex: u32) -> LdEbpfResult<XdpFirewallHandle> {
    use crate::chain::xdp_manager::StageType;
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    use xdp_firewall_skel::XdpFirewallSkelBuilder;

    let paths = &rt.paths;
    let builder = XdpFirewallSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_firewall skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path(),
        ),
        "xdp_firewall pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &paths.xdp_pipe_exits_lan_path(),),
        "xdp_firewall pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &paths.xdp_pipe_exits_wan_path(),),
        "xdp_firewall pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_firewall pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip4_map, &paths.firewall_ipv4_block,),
        "xdp_firewall pin firewall_block_ip4_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip6_map, &paths.firewall_ipv6_block,),
        "xdp_firewall pin firewall_block_ip6_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.firewall_conn_metric_events,
            &paths.firewall_conn_metric_events,
        ),
        "xdp_firewall pin firewall_conn_metric_events"
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load xdp_firewall skeleton")?;

    let lan_fd = skel.progs.xdp_firewall_lan.as_fd().as_raw_fd();
    let wan_fd = skel.progs.xdp_firewall_wan.as_fd().as_raw_fd();
    let next_fd = skel.maps.next_stage.as_fd().as_raw_fd();

    rt.xdp.inject(ifindex, StageType::Firewall, lan_fd, wan_fd, next_fd)?;

    Ok(XdpFirewallHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        ifindex,
    })
}

// ========================================================================
// Mode-aware unified entry (TC ingress+egress + XDP LAN+WAN)
// ========================================================================

pub fn init_firewall(
    rt: &Arc<EbpfRuntime>,
    ifindex: u32,
    has_mac: bool,
) -> LdEbpfResult<FirewallHandle> {
    Ok(FirewallHandle {
        tc: Some(attach_tc_firewall(rt, ifindex, has_mac)?),
        xdp: Some(init_xdp_firewall(rt, ifindex)?),
    })
}
