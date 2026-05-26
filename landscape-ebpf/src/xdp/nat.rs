use std::os::fd::{AsFd, AsRawFd};

use landscape_common::iface::nat::NatConfig;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapCore;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::xdp::manager::{
    xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
    xdp_pipe_root_progs_path, StageType, XdpChainManager,
};
use crate::MAP_PATHS;

pub(crate) mod xdp_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat.skel.rs"));
}

use xdp_nat_skel::XdpNatSkelBuilder;

pub struct XdpNatHandle {
    _skel: xdp_nat_skel::XdpNatSkel<'static>,
    _backing: OwnedOpenObject,
    ifindex: u32,
}

unsafe impl Send for XdpNatHandle {}
unsafe impl Sync for XdpNatHandle {}

impl Drop for XdpNatHandle {
    fn drop(&mut self) {
        let manager = XdpChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Nat);
    }
}

fn seed_port_queue<M>(map: &M, start: u16, end: u16)
where
    M: MapCore,
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

    seed_port_queue(
        &skel.maps.nat4_tcp_free_ports_v3,
        config.tcp_range.start,
        config.tcp_range.end,
    );
    seed_port_queue(
        &skel.maps.nat4_udp_free_ports_v3,
        config.udp_range.start,
        config.udp_range.end,
    );
    seed_port_queue(
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
