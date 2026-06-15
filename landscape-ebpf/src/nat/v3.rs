use std::os::fd::AsRawFd;

use land_nat_v3::*;
use landscape_common::iface::nat::NatConfig;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore,
};

use crate::pipeline::wan_tc::{
    wan_tc_pipeline_egress_path, wan_tc_pipeline_ingress_path, WanTcPipelineHandle,
};
use crate::MAP_PATHS;
use crate::{
    bpf_error::LdEbpfResult,
    landscape::{pin_and_reuse_map, OwnedOpenObject},
    map_setting::reuse_pinned_map_or_recreate,
};

pub(crate) mod land_nat_v3 {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/land_nat_v3.skel.rs"));
}

pub struct NatV3Handle {
    skel: Option<LandNatV3Skel<'static>>,
    _backing: OwnedOpenObject,
    pipeline: Option<WanTcPipelineHandle>,
}

unsafe impl Send for NatV3Handle {}
unsafe impl Sync for NatV3Handle {}

impl NatV3Handle {
    pub fn skel(&self) -> &LandNatV3Skel<'static> {
        self.skel.as_ref().expect("nat v3 skeleton missing")
    }

    pub fn skel_mut(&mut self) -> &mut LandNatV3Skel<'static> {
        self.skel.as_mut().expect("nat v3 skeleton missing")
    }
}

impl Drop for NatV3Handle {
    fn drop(&mut self) {
        if let Some(pipeline) = self.pipeline.as_ref() {
            pipeline.unregister_nat();
        }
        self.pipeline.take();
        self.skel.take();
    }
}

fn seed_port_queue<M>(map: &M, start: u16, end: u16)
where
    M: MapCore,
{
    let fd = map.as_fd().as_raw_fd();
    for port in start..=end {
        let value = types::nat4_port_queue_value_v3 { port: port.to_be(), last_generation: 0 };
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                fd,
                std::ptr::null(),
                (&value as *const types::nat4_port_queue_value_v3).cast_mut().cast(),
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

pub fn init_nat(ifindex: i32, has_mac: bool, config: NatConfig) -> LdEbpfResult<NatV3Handle> {
    let landscape_builder = LandNatV3SkelBuilder::default();
    let (backing, open_object) = OwnedOpenObject::new();
    let mut landscape_open =
        crate::bpf_ctx!(landscape_builder.open(open_object), "nat_v3 open skeleton failed")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut landscape_open.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "nat_v3 prepare wan_ip_binding failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut landscape_open.maps.nat6_static_mappings,
            &MAP_PATHS.nat6_static_mappings
        ),
        "nat_v3 prepare nat6_static_mappings failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut landscape_open.maps.nat4_st_map, &MAP_PATHS.nat4_st_map),
        "nat_v3 prepare nat4_st_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut landscape_open.maps.nat_conn_metric_events,
            &MAP_PATHS.nat_conn_metric_events
        ),
        "nat_v3 prepare nat_conn_metric_events failed"
    )?;
    let ingress_pipeline_path = wan_tc_pipeline_ingress_path(ifindex as u32);
    let egress_pipeline_path = wan_tc_pipeline_egress_path(ifindex as u32);
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.ingress_stage_progs,
        &ingress_pipeline_path,
    );
    reuse_pinned_map_or_recreate(
        &mut landscape_open.maps.egress_stage_progs,
        &egress_pipeline_path,
    );

    let rodata_data =
        landscape_open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");

    rodata_data.tcp_range_start = config.tcp_range.start;
    rodata_data.tcp_range_end = config.tcp_range.end;
    rodata_data.udp_range_start = config.udp_range.start;
    rodata_data.udp_range_end = config.udp_range.end;
    rodata_data.icmp_range_start = config.icmp_in_range.start;
    rodata_data.icmp_range_end = config.icmp_in_range.end;

    if !has_mac {
        rodata_data.current_l3_offset = 0;
    }

    let landscape_skel = crate::bpf_ctx!(landscape_open.load(), "nat_v3 load skeleton failed")?;

    seed_runtime_queues(
        &landscape_skel.maps.nat4_tcp_free_ports_v3,
        &landscape_skel.maps.nat4_udp_free_ports_v3,
        &landscape_skel.maps.nat4_icmp_free_ports_v3,
        &config,
    );
    let pipeline = WanTcPipelineHandle::acquire(ifindex as u32)?;
    pipeline.register_nat(&landscape_skel.progs.ingress_nat, &landscape_skel.progs.egress_nat)?;

    Ok(NatV3Handle {
        _backing: backing,
        skel: Some(landscape_skel),
        pipeline: Some(pipeline),
    })
}
