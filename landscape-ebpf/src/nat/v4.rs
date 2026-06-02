use std::os::fd::{AsFd, AsRawFd};

use landscape_common::iface::nat::NatConfig;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore,
};

use crate::bpf_error::LdEbpfResult;
use crate::chain::xdp_manager::{
    xdp_lan_pipe_root_progs_path, xdp_pipe_exits_lan_path, xdp_pipe_exits_wan_path,
    xdp_pipe_root_progs_path, StageType, XdpChainManager,
};
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::map_setting::reuse_pinned_map_or_recreate;
use crate::pipeline::wan_tc::{
    wan_tc_pipeline_egress_path, wan_tc_pipeline_ingress_path, WanTcPipelineHandle,
};
use crate::MAP_PATHS;

pub(crate) mod xdp_nat {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat.skel.rs"));
}

pub(crate) mod land_nat_v3 {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_nat_v3.skel.rs"));
}

use land_nat_v3::{LandNatV3Skel, LandNatV3SkelBuilder};
use xdp_nat::{XdpNatSkel, XdpNatSkelBuilder};

pub struct NatV4Handle {
    _tc_backing: OwnedOpenObject,
    _xdp_backing: OwnedOpenObject,
    tc_skel: Option<LandNatV3Skel<'static>>,
    xdp_skel: Option<XdpNatSkel<'static>>,
    pipeline: Option<WanTcPipelineHandle>,
    ifindex: u32,
}

unsafe impl Send for NatV4Handle {}
unsafe impl Sync for NatV4Handle {}

impl NatV4Handle {
    pub fn skel(&self) -> &LandNatV3Skel<'static> {
        self.tc_skel.as_ref().expect("nat v4 tc skeleton missing")
    }

    pub fn skel_mut(&mut self) -> &mut LandNatV3Skel<'static> {
        self.tc_skel.as_mut().expect("nat v4 tc skeleton missing")
    }
}

impl Drop for NatV4Handle {
    fn drop(&mut self) {
        let manager = XdpChainManager::instance();
        let _ = manager.remove(self.ifindex, StageType::Nat);
        if let Some(pipeline) = self.pipeline.as_ref() {
            pipeline.unregister_nat();
        }
        self.pipeline.take();
        self.xdp_skel.take();
        self.tc_skel.take();
    }
}

fn seed_port_queue<M>(map: &M, start: u16, end: u16)
where
    M: MapCore,
{
    let fd = map.as_fd().as_raw_fd();
    for port in start..=end {
        let value =
            land_nat_v3::types::nat4_port_queue_value_v3 { port: port.to_be(), last_generation: 0 };
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                fd,
                std::ptr::null(),
                (&value as *const land_nat_v3::types::nat4_port_queue_value_v3).cast_mut().cast(),
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

pub fn init_nat_v4(ifindex: u32, has_mac: bool, config: &NatConfig) -> LdEbpfResult<NatV4Handle> {
    // ── Step 1: Load TC NAT skeleton first (creates shared runtime maps) ──
    let landscape_builder = LandNatV3SkelBuilder::default();
    let (tc_backing, tc_open_object) = OwnedOpenObject::new();
    let mut tc_open =
        crate::bpf_ctx!(landscape_builder.open(tc_open_object), "nat_v4 TC open skeleton failed")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut tc_open.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "nat_v4 TC prepare wan_ip_binding failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut tc_open.maps.nat6_static_mappings, &MAP_PATHS.nat6_static_mappings),
        "nat_v4 TC prepare nat6_static_mappings failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut tc_open.maps.nat4_st_map, &MAP_PATHS.nat4_st_map),
        "nat_v4 TC prepare nat4_st_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut tc_open.maps.nat_conn_metric_events,
            &MAP_PATHS.nat_conn_metric_events
        ),
        "nat_v4 TC prepare nat_conn_metric_events failed"
    )?;

    let ingress_pipeline_path = wan_tc_pipeline_ingress_path(ifindex);
    let egress_pipeline_path = wan_tc_pipeline_egress_path(ifindex);
    reuse_pinned_map_or_recreate(&mut tc_open.maps.ingress_stage_progs, &ingress_pipeline_path);
    reuse_pinned_map_or_recreate(&mut tc_open.maps.egress_stage_progs, &egress_pipeline_path);

    let tc_rodata =
        tc_open.maps.rodata_data.as_deref_mut().expect("nat_v4 TC rodata not memory mapped");
    tc_rodata.tcp_range_start = config.tcp_range.start;
    tc_rodata.tcp_range_end = config.tcp_range.end;
    tc_rodata.udp_range_start = config.udp_range.start;
    tc_rodata.udp_range_end = config.udp_range.end;
    tc_rodata.icmp_range_start = config.icmp_in_range.start;
    tc_rodata.icmp_range_end = config.icmp_in_range.end;
    if !has_mac {
        tc_rodata.current_l3_offset = 0;
    }

    let tc_skel = crate::bpf_ctx!(tc_open.load(), "nat_v4 TC load skeleton failed")?;

    // ── Step 2: Seed port queues once on TC's maps ──
    seed_runtime_queues(
        &tc_skel.maps.nat4_tcp_free_ports_v3,
        &tc_skel.maps.nat4_udp_free_ports_v3,
        &tc_skel.maps.nat4_icmp_free_ports_v3,
        config,
    );

    // ── Step 3: Open XDP NAT skeleton ──
    let xdp_builder = XdpNatSkelBuilder::default();
    let (xdp_backing, xdp_obj) = OwnedOpenObject::new();
    let mut xdp_open =
        crate::bpf_ctx!(xdp_builder.open(xdp_obj), "nat_v4 XDP open skeleton failed")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path()),
        "nat_v4 XDP pin xdp_pipe_root_progs"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path()),
        "nat_v4 XDP pin xdp_pipe_exits_lan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path()),
        "nat_v4 XDP pin xdp_pipe_exits_wan"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path()
        ),
        "nat_v4 XDP pin xdp_lan_pipe_root_progs"
    )?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "nat_v4 XDP pin wan_ip_binding"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat6_static_mappings, &MAP_PATHS.nat6_static_mappings),
        "nat_v4 XDP pin nat6_static_mappings"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut xdp_open.maps.nat4_st_map, &MAP_PATHS.nat4_st_map),
        "nat_v4 XDP pin nat4_st_map"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut xdp_open.maps.nat_conn_metric_events,
            &MAP_PATHS.nat_conn_metric_events
        ),
        "nat_v4 XDP pin nat_conn_metric_events"
    )?;

    {
        let xdp_rodata =
            xdp_open.maps.rodata_data.as_deref_mut().expect("nat_v4 XDP rodata not memory mapped");
        xdp_rodata.current_ifindex = ifindex;
        xdp_rodata.tcp_range_start = config.tcp_range.start;
        xdp_rodata.tcp_range_end = config.tcp_range.end;
        xdp_rodata.udp_range_start = config.udp_range.start;
        xdp_rodata.udp_range_end = config.udp_range.end;
        xdp_rodata.icmp_range_start = config.icmp_in_range.start;
        xdp_rodata.icmp_range_end = config.icmp_in_range.end;
    }

    // ── Step 4: Reuse TC's map FDs in XDP (before XDP load) ──
    crate::bpf_ctx!(
        xdp_open.maps.nat4_dyn_map.reuse_fd(tc_skel.maps.nat4_dyn_map.as_fd()),
        "nat_v4 XDP reuse nat4_dyn_map fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_mapping_timer_v3.reuse_fd(tc_skel.maps.nat4_mapping_timer_v3.as_fd()),
        "nat_v4 XDP reuse nat4_mapping_timer_v3 fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_tcp_free_ports_v3.reuse_fd(tc_skel.maps.nat4_tcp_free_ports_v3.as_fd()),
        "nat_v4 XDP reuse nat4_tcp_free_ports_v3 fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat4_udp_free_ports_v3.reuse_fd(tc_skel.maps.nat4_udp_free_ports_v3.as_fd()),
        "nat_v4 XDP reuse nat4_udp_free_ports_v3 fd"
    )?;
    crate::bpf_ctx!(
        xdp_open
            .maps
            .nat4_icmp_free_ports_v3
            .reuse_fd(tc_skel.maps.nat4_icmp_free_ports_v3.as_fd()),
        "nat_v4 XDP reuse nat4_icmp_free_ports_v3 fd"
    )?;
    crate::bpf_ctx!(
        xdp_open.maps.nat6_conn_timer.reuse_fd(tc_skel.maps.nat6_conn_timer.as_fd()),
        "nat_v4 XDP reuse nat6_conn_timer fd"
    )?;

    // ── Step 5: Load XDP skeleton (now sharing TC's runtime maps) ──
    let xdp_skel = crate::bpf_ctx!(xdp_open.load(), "nat_v4 XDP load skeleton failed")?;

    // ── Step 6: Register with both pipelines ──
    let pipeline = WanTcPipelineHandle::acquire(ifindex)?;
    pipeline.register_nat(&tc_skel.progs.ingress_nat, &tc_skel.progs.egress_nat)?;

    let lan_fd = xdp_skel.progs.egress_nat.as_fd().as_raw_fd();
    let wan_fd = xdp_skel.progs.ingress_nat.as_fd().as_raw_fd();
    let next_fd = xdp_skel.maps.next_stage.as_fd().as_raw_fd();

    let manager = XdpChainManager::instance();
    manager.inject(ifindex, StageType::Nat, lan_fd, wan_fd, next_fd)?;

    Ok(NatV4Handle {
        _tc_backing: tc_backing,
        _xdp_backing: xdp_backing,
        tc_skel: Some(tc_skel),
        xdp_skel: Some(xdp_skel),
        pipeline: Some(pipeline),
        ifindex,
    })
}
