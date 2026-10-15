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
    link_chain_id: u16,
}

impl Drop for TcFirewallHandle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        for family in StageFamily::ALL {
            let _ = self.runtime.tc.remove_from_wan(
                self.link_chain_id,
                FromWanStageType::Firewall,
                family,
            );
            let _ = self.runtime.tc.remove_from_lan(
                self.link_chain_id,
                FromLanStageType::Firewall,
                family,
            );
        }
    }
}

pub fn attach_tc_firewall(
    rt: &Arc<EbpfRuntime>,
    link_chain_id: u16,
    has_eth_header: bool,
) -> LdEbpfResult<TcFirewallHandle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, FromWanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let paths = &rt.paths;

    let builder = tc_firewall_skel::TcFirewallSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_firewall skeleton")?;

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

    pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip4_map, &paths.firewall_ipv4_block)?;
    pin_and_reuse_map(&mut open_skel.maps.firewall_block_ip6_map, &paths.firewall_ipv6_block)?;
    pin_and_reuse_map(
        &mut open_skel.maps.firewall_conn_metric_events,
        &paths.firewall_conn_metric_events,
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_firewall skeleton")?;

    let next_ingress_fd = skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd();
    let next_egress_fd = skel.maps.wan_egress_next_stage.as_fd().as_raw_fd();
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.tc_firewall_wan_ingress_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.tc_firewall_wan_ingress_v6.as_fd().as_raw_fd()),
    ] {
        rt.tc.inject_from_wan(
            link_chain_id,
            FromWanStageType::Firewall,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_ingress_fd },
        )?;
    }
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.tc_firewall_wan_egress_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.tc_firewall_wan_egress_v6.as_fd().as_raw_fd()),
    ] {
        rt.tc.inject_from_lan(
            link_chain_id,
            FromLanStageType::Firewall,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_egress_fd },
        )?;
    }

    Ok(TcFirewallHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        link_chain_id,
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
    link_chain_id: u16,
}

unsafe impl Send for XdpFirewallHandle {}
unsafe impl Sync for XdpFirewallHandle {}

impl Drop for XdpFirewallHandle {
    fn drop(&mut self) {
        use crate::chain::stage::{FromLanStageType, FromWanStageType, StageFamily};
        for family in StageFamily::ALL {
            let _ = self.runtime.xdp.remove_from_wan(
                self.link_chain_id,
                FromWanStageType::Firewall,
                family,
            );
            let _ = self.runtime.xdp.remove_from_lan(
                self.link_chain_id,
                FromLanStageType::Firewall,
                family,
            );
        }
    }
}

pub fn init_xdp_firewall(
    rt: &Arc<EbpfRuntime>,
    link_chain_id: u16,
) -> LdEbpfResult<XdpFirewallHandle> {
    use crate::chain::stage::{FamilyProg, FromLanStageType, FromWanStageType, StageFamily};
    use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
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

    let next_stage_fd = skel.maps.next_stage.as_fd().as_raw_fd();
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.xdp_firewall_wan_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.xdp_firewall_wan_v6.as_fd().as_raw_fd()),
    ] {
        rt.xdp.inject_from_wan(
            link_chain_id,
            FromWanStageType::Firewall,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_stage_fd },
        )?;
    }
    for (family, prog_fd) in [
        (StageFamily::V4, skel.progs.xdp_firewall_lan_v4.as_fd().as_raw_fd()),
        (StageFamily::V6, skel.progs.xdp_firewall_lan_v6.as_fd().as_raw_fd()),
    ] {
        rt.xdp.inject_from_lan(
            link_chain_id,
            FromLanStageType::Firewall,
            family,
            FamilyProg { prog_fd, next_stage_map_fd: next_stage_fd },
        )?;
    }

    Ok(XdpFirewallHandle {
        runtime: rt.clone(),
        _skel: skel,
        _backing: backing,
        link_chain_id,
    })
}

// ========================================================================
// Mode-aware unified entry (TC ingress+egress + XDP LAN+WAN)
// ========================================================================

pub fn init_firewall(
    rt: &Arc<EbpfRuntime>,
    link_chain_id: u16,
    has_eth_header: bool,
) -> LdEbpfResult<FirewallHandle> {
    Ok(FirewallHandle {
        tc: Some(attach_tc_firewall(rt, link_chain_id, has_eth_header)?),
        xdp: Some(init_xdp_firewall(rt, link_chain_id)?),
    })
}
