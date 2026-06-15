use libbpf_rs::skel::{OpenSkel, SkelBuilder};

pub(crate) mod firewall_bpf {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/firewall.skel.rs"));
}

use firewall_bpf::*;

use crate::pipeline::wan_tc::{
    wan_tc_pipeline_egress_path, wan_tc_pipeline_ingress_path, WanTcPipelineHandle,
};
use crate::{
    bpf_error::LdEbpfResult,
    landscape::{pin_and_reuse_map, OwnedOpenObject},
    map_setting::reuse_pinned_map_or_recreate,
    MAP_PATHS,
};

pub struct FirewallHandle {
    skel: Option<FirewallSkel<'static>>,
    _backing: OwnedOpenObject,
    pipeline: Option<WanTcPipelineHandle>,
}

unsafe impl Send for FirewallHandle {}
unsafe impl Sync for FirewallHandle {}

impl FirewallHandle {
    pub fn skel(&self) -> &FirewallSkel<'static> {
        self.skel.as_ref().expect("firewall skeleton missing")
    }

    pub fn skel_mut(&mut self) -> &mut FirewallSkel<'static> {
        self.skel.as_mut().expect("firewall skeleton missing")
    }
}

impl Drop for FirewallHandle {
    fn drop(&mut self) {
        if let Some(pipeline) = self.pipeline.as_ref() {
            pipeline.unregister_firewall();
        }
        self.pipeline.take();
        self.skel.take();
    }
}

pub fn new_firewall(ifindex: i32, has_mac: bool) -> LdEbpfResult<FirewallHandle> {
    let firewall_builder = FirewallSkelBuilder::default();
    let (backing, open_object) = OwnedOpenObject::new();
    let mut open_skel =
        crate::bpf_ctx!(firewall_builder.open(open_object), "firewall open skeleton failed")?;
    let rodata_data =
        open_skel.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");

    if !has_mac {
        rodata_data.current_l3_offset = 0;
    }

    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.firewall_block_ip4_map,
            &MAP_PATHS.firewall_ipv4_block
        ),
        "firewall prepare firewall_block_ip4_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.firewall_block_ip6_map,
            &MAP_PATHS.firewall_ipv6_block
        ),
        "firewall prepare firewall_block_ip6_map failed"
    )?;
    crate::bpf_ctx!(
        pin_and_reuse_map(
            &mut open_skel.maps.firewall_conn_metric_events,
            &MAP_PATHS.firewall_conn_metric_events
        ),
        "firewall prepare firewall_conn_metric_events failed"
    )?;
    let ingress_pipeline_path = wan_tc_pipeline_ingress_path(ifindex as u32);
    let egress_pipeline_path = wan_tc_pipeline_egress_path(ifindex as u32);
    reuse_pinned_map_or_recreate(&mut open_skel.maps.ingress_stage_progs, &ingress_pipeline_path);
    reuse_pinned_map_or_recreate(&mut open_skel.maps.egress_stage_progs, &egress_pipeline_path);

    let skel = crate::bpf_ctx!(open_skel.load(), "firewall load skeleton failed")?;
    let pipeline = WanTcPipelineHandle::acquire(ifindex as u32)?;
    pipeline.register_firewall(&skel.progs.ingress_firewall, &skel.progs.egress_firewall)?;

    Ok(FirewallHandle {
        _backing: backing,
        skel: Some(skel),
        pipeline: Some(pipeline),
    })
}
