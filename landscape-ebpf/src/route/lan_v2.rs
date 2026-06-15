pub(crate) mod route_lan {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/route_lan.skel.rs"));
}

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use route_lan::*;

use crate::pipeline::lan_tc::{
    lan_tc_pipeline_egress_path, lan_tc_pipeline_ingress_path, LanTcPipelineHandle,
};
use crate::{
    bpf_error::LdEbpfResult,
    landscape::{pin_and_reuse_map, OwnedOpenObject},
    map_setting::reuse_pinned_map_or_recreate,
    MAP_PATHS,
};

pub struct RouteLanHandle {
    skel: Option<RouteLanSkel<'static>>,
    _backing: OwnedOpenObject,
    pipeline: Option<LanTcPipelineHandle>,
}

unsafe impl Send for RouteLanHandle {}
unsafe impl Sync for RouteLanHandle {}

impl RouteLanHandle {
    pub fn skel(&self) -> &RouteLanSkel<'static> {
        self.skel.as_ref().expect("route lan skeleton missing")
    }

    pub fn skel_mut(&mut self) -> &mut RouteLanSkel<'static> {
        self.skel.as_mut().expect("route lan skeleton missing")
    }
}

impl Drop for RouteLanHandle {
    fn drop(&mut self) {
        if let Some(pipeline) = self.pipeline.as_ref() {
            pipeline.unregister_route_lan();
        }
        self.pipeline.take();
        self.skel.take();
    }
}

pub fn route_lan(ifindex: u32, has_mac: bool) -> LdEbpfResult<RouteLanHandle> {
    let firewall_builder = RouteLanSkelBuilder::default();
    let (backing, open_object) = OwnedOpenObject::new();
    let mut open_skel =
        crate::bpf_ctx!(firewall_builder.open(open_object), "route_lan open skeleton failed")?;

    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &MAP_PATHS.flow_match_map),
        "route_lan prepare flow_match_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
        "route_lan prepare wan_ip_binding failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &MAP_PATHS.rt4_lan_map),
        "route_lan prepare rt4_lan_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &MAP_PATHS.rt6_lan_map),
        "route_lan prepare rt6_lan_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_target_slot_map, &MAP_PATHS.rt4_target_slot_map),
        "route_lan prepare rt4_target_slot_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_target_slot_map, &MAP_PATHS.rt6_target_slot_map),
        "route_lan prepare rt6_target_slot_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &MAP_PATHS.flow4_dns_map),
        "route_lan prepare flow4_dns_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &MAP_PATHS.flow6_dns_map),
        "route_lan prepare flow6_dns_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &MAP_PATHS.flow4_ip_map),
        "route_lan prepare flow4_ip_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &MAP_PATHS.flow6_ip_map),
        "route_lan prepare flow6_ip_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &MAP_PATHS.rt4_cache_map),
        "route_lan prepare rt4_cache_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &MAP_PATHS.rt6_cache_map),
        "route_lan prepare rt6_cache_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &MAP_PATHS.ip_mac_v4),
        "route_lan prepare ip_mac_v4 failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &MAP_PATHS.ip_mac_v6),
        "route_lan prepare ip_mac_v6 failed"
    )?;
    let ingress_pipeline_path = lan_tc_pipeline_ingress_path(ifindex);
    let egress_pipeline_path = lan_tc_pipeline_egress_path(ifindex);
    reuse_pinned_map_or_recreate(
        &mut open_skel.maps.lan_ingress_stage_progs,
        &ingress_pipeline_path,
    );
    reuse_pinned_map_or_recreate(&mut open_skel.maps.lan_egress_stage_progs, &egress_pipeline_path);

    let rodata_data =
        open_skel.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");
    if !has_mac {
        rodata_data.current_l3_offset = 0;
    }

    let skel = crate::bpf_ctx!(open_skel.load(), "route_lan load skeleton failed")?;
    let pipeline = LanTcPipelineHandle::acquire(ifindex)?;
    pipeline.register_route_lan(&skel.progs.route_lan_ingress, &skel.progs.route_lan_egress)?;

    Ok(RouteLanHandle {
        _backing: backing,
        skel: Some(skel),
        pipeline: Some(pipeline),
    })
}
