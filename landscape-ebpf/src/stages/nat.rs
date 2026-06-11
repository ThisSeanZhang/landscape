use std::os::fd::AsRawFd;

use landscape_common::iface::nat::NatConfig;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;

// ========================================================================
// TC NAT
// ========================================================================

mod tc_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_nat.skel.rs"));
}

pub(crate) mod xdp_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat.skel.rs"));
}

pub struct NatHandle {
    pub tc: Option<TcNatHandle>,
    pub xdp: Option<XdpNatHandle>,
}

pub struct TcNatHandle {
    _skel: tc_nat_skel::TcNatSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

impl Drop for TcNatHandle {
    fn drop(&mut self) {
        use crate::chain::tc_manager::{StageType, TcChainManager};
        let manager = TcChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Nat);
    }
}

pub struct XdpNatHandle {
    _skel: xdp_nat_skel::XdpNatSkel<'static>,
    _backing: crate::landscape::OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpNatHandle {}
unsafe impl Sync for XdpNatHandle {}

impl Drop for XdpNatHandle {
    fn drop(&mut self) {
        use crate::chain::xdp_manager::{StageType, XdpChainManager};
        let manager = XdpChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Nat);
    }
}

fn seed_port_queue<M>(map: &M, start: u16, end: u16)
where
    M: libbpf_rs::MapCore,
{
    let fd = map.as_fd().as_raw_fd();
    for port in start..=end {
        let value =
            tc_nat_skel::types::nat4_port_queue_value_v3 { port: port.to_be(), last_generation: 0 };
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                fd,
                std::ptr::null(),
                (&value as *const tc_nat_skel::types::nat4_port_queue_value_v3).cast_mut().cast(),
                0,
            )
        };
        if ret != 0 {
            break;
        }
    }
}

fn seed_runtime_queues<M1, M2, M3>(
    tcp_queue: &M1,
    udp_queue: &M2,
    icmp_queue: &M3,
    config: &NatConfig,
) where
    M1: libbpf_rs::MapCore,
    M2: libbpf_rs::MapCore,
    M3: libbpf_rs::MapCore,
{
    seed_port_queue(tcp_queue, config.tcp_range.start, config.tcp_range.end);
    seed_port_queue(udp_queue, config.udp_range.start, config.udp_range.end);
    seed_port_queue(icmp_queue, config.icmp_in_range.start, config.icmp_in_range.end);
}

// ========================================================================
// TC NAT — full (ingress + egress, used by TC mode)
// ========================================================================

pub fn attach_tc_nat(ifindex: u32, has_mac: bool, config: &NatConfig) -> LdEbpfResult<TcNatHandle> {
    use crate::chain::tc_manager::{
        tc_pipe_exits_wan_egress_path, tc_pipe_exits_wan_ingress_path, StageEntry, StageType,
        TcChainManager,
    };
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use crate::MAP_PATHS;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    let manager = TcChainManager::instance();
    manager.ensure_roots(ifindex, has_mac)?;

    let builder = tc_nat_skel::TcNatSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_nat skeleton")?;

    let rodata_data =
        open_skel.maps.rodata_data.as_deref_mut().expect("`rodata` is not memory mapped");
    rodata_data.current_l3_offset = if has_mac { 14 } else { 0 };
    rodata_data.tcp_range_start = config.tcp_range.start;
    rodata_data.tcp_range_end = config.tcp_range.end;
    rodata_data.udp_range_start = config.udp_range.start;
    rodata_data.udp_range_end = config.udp_range.end;
    rodata_data.icmp_range_start = config.icmp_in_range.start;
    rodata_data.icmp_range_end = config.icmp_in_range.end;

    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_ingress,
        &tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_wan_egress,
        &tc_pipe_exits_wan_egress_path(),
    )?;

    pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip)?;
    pin_and_reuse_map(&mut open_skel.maps.nat6_static_mappings, &MAP_PATHS.nat6_static_mappings)?;
    pin_and_reuse_map(&mut open_skel.maps.nat4_st_map, &MAP_PATHS.nat4_st_map)?;
    pin_and_reuse_map(
        &mut open_skel.maps.nat_conn_metric_events,
        &MAP_PATHS.nat_conn_metric_events,
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_nat skeleton")?;

    seed_runtime_queues(
        &skel.maps.nat4_tcp_free_ports_v3,
        &skel.maps.nat4_udp_free_ports_v3,
        &skel.maps.nat4_icmp_free_ports_v3,
        config,
    );

    let entry = StageEntry {
        wan_ingress_prog_fd: skel.progs.tc_nat_wan_ingress.as_fd().as_raw_fd(),
        wan_egress_prog_fd: skel.progs.tc_nat_wan_egress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };

    manager.inject(ifindex, StageType::Nat, entry)?;

    Ok(TcNatHandle { _skel: skel, _backing: backing, ifindex })
}

// ========================================================================
// Unified XDP+TC NAT (XDP mode only, FD sharing for runtime maps)
// ========================================================================

fn init_nat_xdp_unified(
    ifindex: u32,
    has_mac: bool,
    config: &NatConfig,
) -> LdEbpfResult<(TcNatHandle, XdpNatHandle)> {
    use crate::chain::tc_manager::{
        tc_pipe_exits_wan_egress_path, tc_pipe_exits_wan_ingress_path, StageEntry, StageType,
        TcChainManager,
    };
    use crate::chain::xdp_manager::{
        xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
        xdp_pipe_root_progs_path, StageType as XdpStageType, XdpChainManager,
    };
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use crate::MAP_PATHS;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    // ── 1. Load TC nat first (ingress + egress, for runtime map sharing with XDP) ──

    let tc_manager = TcChainManager::instance();
    tc_manager.ensure_roots(ifindex, has_mac)?;

    let tc_builder = tc_nat_skel::TcNatSkelBuilder::default();
    let (tc_backing, tc_obj) = OwnedOpenObject::new();
    let mut tc_open = bpf_ctx!(tc_builder.open(tc_obj), "open tc_nat skeleton")?;

    let tc_rodata = tc_open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memory mapped");
    tc_rodata.current_l3_offset = if has_mac { 14 } else { 0 };
    tc_rodata.tcp_range_start = config.tcp_range.start;
    tc_rodata.tcp_range_end = config.tcp_range.end;
    tc_rodata.udp_range_start = config.udp_range.start;
    tc_rodata.udp_range_end = config.udp_range.end;
    tc_rodata.icmp_range_start = config.icmp_in_range.start;
    tc_rodata.icmp_range_end = config.icmp_in_range.end;

    pin_and_reuse_map(
        &mut tc_open.maps.tc_pipe_exits_wan_ingress,
        &tc_pipe_exits_wan_ingress_path(),
    )?;
    pin_and_reuse_map(
        &mut tc_open.maps.tc_pipe_exits_wan_egress,
        &tc_pipe_exits_wan_egress_path(),
    )?;
    pin_and_reuse_map(&mut tc_open.maps.wan_ip_binding, &MAP_PATHS.wan_ip)?;
    pin_and_reuse_map(&mut tc_open.maps.nat6_static_mappings, &MAP_PATHS.nat6_static_mappings)?;
    pin_and_reuse_map(&mut tc_open.maps.nat4_st_map, &MAP_PATHS.nat4_st_map)?;
    pin_and_reuse_map(&mut tc_open.maps.nat_conn_metric_events, &MAP_PATHS.nat_conn_metric_events)?;

    let tc_skel = bpf_ctx!(tc_open.load(), "load tc_nat skeleton")?;

    seed_runtime_queues(
        &tc_skel.maps.nat4_tcp_free_ports_v3,
        &tc_skel.maps.nat4_udp_free_ports_v3,
        &tc_skel.maps.nat4_icmp_free_ports_v3,
        config,
    );

    // ── 2. Open XDP nat, reuse TC's runtime map FDs ──

    let xdp_builder = xdp_nat_skel::XdpNatSkelBuilder::default();
    let (xdp_backing, xdp_obj) = OwnedOpenObject::new();
    let mut xdp_open = bpf_ctx!(xdp_builder.open(xdp_obj), "open xdp_nat skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path()),
        "xdp_nat pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path()),
        "xdp_nat pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path()),
        "xdp_nat pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_nat pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "xdp_nat pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat6_static_mappings, &MAP_PATHS.nat6_static_mappings,),
        "xdp_nat pin nat6_static_mappings"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat4_st_map, &MAP_PATHS.nat4_st_map),
        "xdp_nat pin nat4_st_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.nat_conn_metric_events,
            &MAP_PATHS.nat_conn_metric_events,
        ),
        "xdp_nat pin nat_conn_metric_events"
    )?;

    // Reuse TC's runtime map FDs in XDP (FD sharing, no pinning)
    crate::bpf_ctx!(
        xdp_open.maps.nat4_dyn_map.reuse_fd(tc_skel.maps.nat4_dyn_map.as_fd()),
        "xdp_nat reuse nat4_dyn_map fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_mapping_timer_v3.reuse_fd(tc_skel.maps.nat4_mapping_timer_v3.as_fd()),
        "xdp_nat reuse nat4_mapping_timer_v3 fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_tcp_free_ports_v3.reuse_fd(tc_skel.maps.nat4_tcp_free_ports_v3.as_fd()),
        "xdp_nat reuse nat4_tcp_free_ports_v3 fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_udp_free_ports_v3.reuse_fd(tc_skel.maps.nat4_udp_free_ports_v3.as_fd()),
        "xdp_nat reuse nat4_udp_free_ports_v3 fd"
    )?;
    crate::bpf_ctx!(
        xdp_open
            .maps
            .nat4_icmp_free_ports_v3
            .reuse_fd(tc_skel.maps.nat4_icmp_free_ports_v3.as_fd()),
        "xdp_nat reuse nat4_icmp_free_ports_v3 fd"
    )?;

    {
        let xdp_rodata =
            xdp_open.maps.rodata_data.as_deref_mut().expect("xdp_nat rodata not memory mapped");
        xdp_rodata.current_ifindex = ifindex;
        xdp_rodata.tcp_range_start = config.tcp_range.start;
        xdp_rodata.tcp_range_end = config.tcp_range.end;
        xdp_rodata.udp_range_start = config.udp_range.start;
        xdp_rodata.udp_range_end = config.udp_range.end;
        xdp_rodata.icmp_range_start = config.icmp_in_range.start;
        xdp_rodata.icmp_range_end = config.icmp_in_range.end;
    }

    let xdp_skel = bpf_ctx!(xdp_open.load(), "load xdp_nat skeleton")?;

    // ── 3. Inject into chain managers ──

    let tc_entry = StageEntry {
        wan_ingress_prog_fd: tc_skel.progs.tc_nat_wan_ingress.as_fd().as_raw_fd(),
        wan_egress_prog_fd: tc_skel.progs.tc_nat_wan_egress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: tc_skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: tc_skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
    };
    tc_manager.inject(ifindex, StageType::Nat, tc_entry)?;

    let xdp_lan_fd = xdp_skel.progs.egress_nat.as_fd().as_raw_fd();
    let xdp_wan_fd = xdp_skel.progs.ingress_nat.as_fd().as_raw_fd();
    let xdp_next_fd = xdp_skel.maps.next_stage.as_fd().as_raw_fd();
    let xdp_manager = XdpChainManager::instance();
    xdp_manager.inject(ifindex, XdpStageType::Nat, xdp_lan_fd, xdp_wan_fd, xdp_next_fd)?;

    Ok((
        TcNatHandle { _skel: tc_skel, _backing: tc_backing, ifindex },
        XdpNatHandle { _skel: xdp_skel, _backing: xdp_backing, ifindex },
    ))
}

// ========================================================================
// Mode-aware unified entry
// ========================================================================

pub fn init_nat(ifindex: u32, has_mac: bool, config: &NatConfig) -> LdEbpfResult<NatHandle> {
    let (tc, xdp) = init_nat_xdp_unified(ifindex, has_mac, config)?;
    Ok(NatHandle { tc: Some(tc), xdp: Some(xdp) })
}
