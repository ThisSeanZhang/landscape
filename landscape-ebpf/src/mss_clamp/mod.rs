pub(crate) mod mss_clamp {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/mss_clamp.skel.rs"));
}

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use mss_clamp::*;

use crate::pipeline::wan_tc::{
    wan_tc_pipeline_egress_path, wan_tc_pipeline_ingress_path, WanTcPipelineHandle,
};
use crate::{
    bpf_error::LdEbpfResult, landscape::OwnedOpenObject, map_setting::reuse_pinned_map_or_recreate,
};

pub struct MssClampHandle {
    skel: Option<MssClampSkel<'static>>,
    _backing: OwnedOpenObject,
    pipeline: Option<WanTcPipelineHandle>,
}

unsafe impl Send for MssClampHandle {}
unsafe impl Sync for MssClampHandle {}

impl MssClampHandle {
    pub fn skel(&self) -> &MssClampSkel<'static> {
        self.skel.as_ref().expect("mss clamp skeleton missing")
    }

    pub fn skel_mut(&mut self) -> &mut MssClampSkel<'static> {
        self.skel.as_mut().expect("mss clamp skeleton missing")
    }
}

impl Drop for MssClampHandle {
    fn drop(&mut self) {
        if let Some(pipeline) = self.pipeline.as_ref() {
            pipeline.unregister_mss();
        }
        self.pipeline.take();
        self.skel.take();
    }
}

pub fn run_mss_clamp(ifindex: i32, mtu_size: u16, has_mac: bool) -> LdEbpfResult<MssClampHandle> {
    let landscape_builder = MssClampSkelBuilder::default();
    let (backing, open_object) = OwnedOpenObject::new();
    let mut landscape_open =
        crate::bpf_ctx!(landscape_builder.open(open_object), "mss_clamp open skeleton failed")?;

    let rodata_data =
        landscape_open.maps.rodata_data.as_deref_mut().expect("`rodata` is not memery mapped");
    if !has_mac {
        rodata_data.current_l3_offset = 0;
    }

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

    rodata_data.mtu_size = mtu_size;
    let landscape_skel = crate::bpf_ctx!(landscape_open.load(), "mss_clamp load skeleton failed")?;

    let pipeline = WanTcPipelineHandle::acquire(ifindex as u32)?;
    pipeline
        .register_mss(&landscape_skel.progs.clamp_ingress, &landscape_skel.progs.clamp_egress)?;

    Ok(MssClampHandle {
        _backing: backing,
        skel: Some(landscape_skel),
        pipeline: Some(pipeline),
    })
}
