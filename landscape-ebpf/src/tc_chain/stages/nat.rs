use std::os::fd::{AsFd, AsRawFd};

use landscape_common::iface::nat::NatConfig;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore,
};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::tc_chain::manager::{
    tc_pipe_exits_lan_ingress_path, tc_pipe_exits_wan_egress_path, tc_pipe_exits_wan_ingress_path,
    StageEntry, StageType, TcChainManager,
};
use crate::MAP_PATHS;

mod tc_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_nat.skel.rs"));
}

pub struct TcNatHandle {
    _skel: tc_nat_skel::TcNatSkel<'static>,
    _backing: OwnedOpenObject,
    ifindex: u32,
}

impl Drop for TcNatHandle {
    fn drop(&mut self) {
        let manager = TcChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Nat);
    }
}

fn seed_port_queue<M>(map: &M, start: u16, end: u16)
where
    M: MapCore,
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
    M1: MapCore,
    M2: MapCore,
    M3: MapCore,
{
    seed_port_queue(tcp_queue, config.tcp_range.start, config.tcp_range.end);
    seed_port_queue(udp_queue, config.udp_range.start, config.udp_range.end);
    seed_port_queue(icmp_queue, config.icmp_in_range.start, config.icmp_in_range.end);
}

pub fn attach_tc_nat(ifindex: u32, has_mac: bool, config: &NatConfig) -> LdEbpfResult<TcNatHandle> {
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

    seed_runtime_queues(
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
