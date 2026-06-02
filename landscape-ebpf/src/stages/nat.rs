use std::os::fd::AsRawFd;

use landscape_common::args::RouteMode;
use landscape_common::iface::nat::NatConfig;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;

// ========================================================================
// TC NAT
// ========================================================================

mod tc_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_nat.skel.rs"));
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

fn seed_port_queue_tc<M>(map: &M, start: u16, end: u16)
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

fn seed_runtime_queues_tc<M1, M2, M3>(
    tcp_queue: &M1,
    udp_queue: &M2,
    icmp_queue: &M3,
    config: &NatConfig,
) where
    M1: libbpf_rs::MapCore,
    M2: libbpf_rs::MapCore,
    M3: libbpf_rs::MapCore,
{
    seed_port_queue_tc(tcp_queue, config.tcp_range.start, config.tcp_range.end);
    seed_port_queue_tc(udp_queue, config.udp_range.start, config.udp_range.end);
    seed_port_queue_tc(icmp_queue, config.icmp_in_range.start, config.icmp_in_range.end);
}

pub fn attach_tc_nat(ifindex: u32, has_mac: bool, config: &NatConfig) -> LdEbpfResult<TcNatHandle> {
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
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_lan_ingress,
        &tc_pipe_exits_lan_ingress_path(),
    )?;

    pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip)?;
    pin_and_reuse_map(&mut open_skel.maps.nat6_static_mappings, &MAP_PATHS.nat6_static_mappings)?;
    pin_and_reuse_map(&mut open_skel.maps.nat4_st_map, &MAP_PATHS.nat4_st_map)?;
    pin_and_reuse_map(
        &mut open_skel.maps.nat_conn_metric_events,
        &MAP_PATHS.nat_conn_metric_events,
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_nat skeleton")?;

    seed_runtime_queues_tc(
        &skel.maps.nat4_tcp_free_ports_v3,
        &skel.maps.nat4_udp_free_ports_v3,
        &skel.maps.nat4_icmp_free_ports_v3,
        config,
    );

    let entry = StageEntry {
        wan_ingress_prog_fd: skel.progs.tc_nat_wan_ingress.as_fd().as_raw_fd(),
        wan_egress_prog_fd: skel.progs.tc_nat_wan_egress.as_fd().as_raw_fd(),
        lan_ingress_prog_fd: skel.progs.tc_nat_lan_ingress.as_fd().as_raw_fd(),
        wan_ingress_next_stage_fd: skel.maps.wan_ingress_next_stage.as_fd().as_raw_fd(),
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        lan_ingress_next_stage_fd: skel.maps.lan_ingress_next_stage.as_fd().as_raw_fd(),
    };

    manager.inject(ifindex, StageType::Nat, entry)?;

    Ok(TcNatHandle { _skel: skel, _backing: backing, ifindex })
}

// ========================================================================
// XDP NAT
// ========================================================================

pub(crate) mod xdp_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat.skel.rs"));
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

fn seed_port_queue_xdp<M>(map: &M, start: u16, end: u16)
where
    M: libbpf_rs::MapCore,
{
    let fd = map.as_fd().as_raw_fd();
    for port in start..=end {
        let value = xdp_nat_skel::types::nat4_port_queue_value_v3 {
            port: port.to_be(),
            last_generation: 0,
        };
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                fd,
                std::ptr::null(),
                (&value as *const xdp_nat_skel::types::nat4_port_queue_value_v3).cast_mut().cast(),
                0,
            )
        };
        if ret != 0 {
            break;
        }
    }
}

pub fn init_xdp_nat(ifindex: u32, config: &NatConfig) -> LdEbpfResult<XdpNatHandle> {
    use crate::chain::xdp_manager::{
        xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
        xdp_pipe_root_progs_path, StageType, XdpChainManager,
    };
    use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
    use crate::MAP_PATHS;
    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use std::os::fd::{AsFd, AsRawFd};

    use xdp_nat_skel::XdpNatSkelBuilder;

    let builder = XdpNatSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_nat skeleton")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path(),),
        "xdp_nat pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path(),),
        "xdp_nat pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path(),),
        "xdp_nat pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        ),
        "xdp_nat pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "xdp_nat pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.nat6_static_mappings,
            &MAP_PATHS.nat6_static_mappings,
        ),
        "xdp_nat pin nat6_static_mappings"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.nat4_st_map, &MAP_PATHS.nat4_st_map),
        "xdp_nat pin nat4_st_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.nat_conn_metric_events,
            &MAP_PATHS.nat_conn_metric_events,
        ),
        "xdp_nat pin nat_conn_metric_events"
    )?;

    {
        let rodata =
            open_skel.maps.rodata_data.as_deref_mut().expect("xdp_nat rodata not memory mapped");
        rodata.current_ifindex = ifindex;
        rodata.tcp_range_start = config.tcp_range.start;
        rodata.tcp_range_end = config.tcp_range.end;
        rodata.udp_range_start = config.udp_range.start;
        rodata.udp_range_end = config.udp_range.end;
        rodata.icmp_range_start = config.icmp_in_range.start;
        rodata.icmp_range_end = config.icmp_in_range.end;
    }

    let skel = bpf_ctx!(open_skel.load(), "load xdp_nat skeleton")?;

    seed_port_queue_xdp(
        &skel.maps.nat4_tcp_free_ports_v3,
        config.tcp_range.start,
        config.tcp_range.end,
    );
    seed_port_queue_xdp(
        &skel.maps.nat4_udp_free_ports_v3,
        config.udp_range.start,
        config.udp_range.end,
    );
    seed_port_queue_xdp(
        &skel.maps.nat4_icmp_free_ports_v3,
        config.icmp_in_range.start,
        config.icmp_in_range.end,
    );

    let lan_fd = skel.progs.egress_nat.as_fd().as_raw_fd();
    let wan_fd = skel.progs.ingress_nat.as_fd().as_raw_fd();
    let next_fd = skel.maps.next_stage.as_fd().as_raw_fd();

    let manager = XdpChainManager::instance();
    manager.inject(ifindex, StageType::Nat, lan_fd, wan_fd, next_fd)?;

    Ok(XdpNatHandle { _skel: skel, _backing: backing, ifindex })
}

// ========================================================================
// TC NAT — egress only (used by XDP mode for local outbound traffic)
// ========================================================================

pub fn attach_tc_nat_egress(
    ifindex: u32,
    has_mac: bool,
    config: &NatConfig,
) -> LdEbpfResult<TcNatHandle> {
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

    let builder = tc_nat_skel::TcNatSkelBuilder::default();
    let (backing, obj) = OwnedOpenObject::new();
    let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_nat skeleton (egress)")?;

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
    pin_and_reuse_map(
        &mut open_skel.maps.tc_pipe_exits_lan_ingress,
        &tc_pipe_exits_lan_ingress_path(),
    )?;

    pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip)?;
    pin_and_reuse_map(&mut open_skel.maps.nat6_static_mappings, &MAP_PATHS.nat6_static_mappings)?;
    pin_and_reuse_map(&mut open_skel.maps.nat4_st_map, &MAP_PATHS.nat4_st_map)?;
    pin_and_reuse_map(
        &mut open_skel.maps.nat_conn_metric_events,
        &MAP_PATHS.nat_conn_metric_events,
    )?;

    let skel = bpf_ctx!(open_skel.load(), "load tc_nat skeleton (egress)")?;

    seed_runtime_queues_tc(
        &skel.maps.nat4_tcp_free_ports_v3,
        &skel.maps.nat4_udp_free_ports_v3,
        &skel.maps.nat4_icmp_free_ports_v3,
        config,
    );

    let entry = StageEntry {
        wan_ingress_prog_fd: 0,
        wan_egress_prog_fd: skel.progs.tc_nat_wan_egress.as_fd().as_raw_fd(),
        lan_ingress_prog_fd: 0,
        wan_ingress_next_stage_fd: 0,
        wan_egress_next_stage_fd: skel.maps.wan_egress_next_stage.as_fd().as_raw_fd(),
        lan_ingress_next_stage_fd: 0,
    };

    manager.inject(ifindex, StageType::Nat, entry)?;

    Ok(TcNatHandle { _skel: skel, _backing: backing, ifindex })
}

// ========================================================================
// Mode-aware unified entry
// ========================================================================

pub fn init_nat(
    mode: RouteMode,
    ifindex: u32,
    has_mac: bool,
    config: &NatConfig,
) -> LdEbpfResult<NatHandle> {
    match mode {
        RouteMode::Tc => Ok(NatHandle {
            tc: Some(attach_tc_nat(ifindex, has_mac, config)?),
            xdp: None,
        }),
        RouteMode::Xdp => Ok(NatHandle {
            tc: Some(attach_tc_nat_egress(ifindex, has_mac, config)?),
            xdp: Some(init_xdp_nat(ifindex, config)?),
        }),
    }
}
