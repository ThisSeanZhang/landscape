use std::{
    collections::HashMap,
    os::fd::{AsFd, AsRawFd},
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
};

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    MapCore, MapFlags, Program, TC_EGRESS, TC_INGRESS,
};
use once_cell::sync::Lazy;

use crate::{
    bpf_error::LdEbpfResult,
    landscape::{OwnedOpenObject, TcHookProxy},
    map_setting::reuse_pinned_map_or_recreate,
    MAP_PATHS, WAN_ROUTE_EGRESS_PRIORITY, WAN_ROUTE_INGRESS_PRIORITY,
};

pub(crate) mod wan_tc_pipeline {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/wan_tc_pipeline.skel.rs"));
}

use wan_tc_pipeline::*;

pub(crate) const INGRESS_STAGE_MSS: u32 = 1;
pub(crate) const INGRESS_STAGE_FIREWALL: u32 = 2;
pub(crate) const INGRESS_STAGE_WAN_ROUTE: u32 = 4;
pub(crate) const INGRESS_STAGE_COUNT: u32 = 5;
pub(crate) const EGRESS_STAGE_WAN_ROUTE: u32 = 0;
pub(crate) const EGRESS_STAGE_MSS: u32 = 1;
pub(crate) const EGRESS_STAGE_FIREWALL: u32 = 3;
pub(crate) const EGRESS_STAGE_COUNT: u32 = 5;

static PIPELINES: Lazy<Mutex<HashMap<u32, Weak<WanTcPipelineInner>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

pub(crate) fn wan_tc_pipeline_ingress_path(ifindex: u32) -> PathBuf {
    MAP_PATHS.wan_tc_pipeline_ingress.with_file_name(format!("wan_tc_pipeline_ingress_{ifindex}"))
}

pub(crate) fn wan_tc_pipeline_egress_path(ifindex: u32) -> PathBuf {
    MAP_PATHS.wan_tc_pipeline_egress.with_file_name(format!("wan_tc_pipeline_egress_{ifindex}"))
}

pub struct WanTcPipelineHandle {
    inner: Arc<WanTcPipelineInner>,
}

struct WanTcPipelineInner {
    skel: WanTcPipelineSkel<'static>,
    _backing: OwnedOpenObject,
    ingress_hook: Mutex<Option<TcHookProxy>>,
    egress_hook: Mutex<Option<TcHookProxy>>,
    ifindex: u32,
}

unsafe impl Send for WanTcPipelineHandle {}
unsafe impl Sync for WanTcPipelineHandle {}
unsafe impl Send for WanTcPipelineInner {}
unsafe impl Sync for WanTcPipelineInner {}

impl WanTcPipelineHandle {
    pub fn acquire(ifindex: u32) -> LdEbpfResult<Self> {
        let mut pipelines = PIPELINES.lock().expect("wan tc pipeline registry poisoned");
        if let Some(existing) = pipelines.get(&ifindex).and_then(Weak::upgrade) {
            return Ok(Self { inner: existing });
        }

        let inner = Arc::new(WanTcPipelineInner::new(ifindex)?);
        pipelines.insert(ifindex, Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    pub fn register_route_wan(
        &self,
        ingress_prog: &Program,
        egress_prog: &Program,
    ) -> LdEbpfResult<()> {
        register_stage(
            &self.inner.skel.maps.ingress_stage_progs,
            INGRESS_STAGE_WAN_ROUTE,
            ingress_prog,
        )?;
        register_stage(
            &self.inner.skel.maps.egress_stage_progs,
            EGRESS_STAGE_WAN_ROUTE,
            egress_prog,
        )?;
        Ok(())
    }

    pub fn unregister_route_wan(&self) {
        let _ =
            self.inner.skel.maps.ingress_stage_progs.delete(&INGRESS_STAGE_WAN_ROUTE.to_ne_bytes());
        let _ =
            self.inner.skel.maps.egress_stage_progs.delete(&EGRESS_STAGE_WAN_ROUTE.to_ne_bytes());
    }

    pub fn register_firewall(
        &self,
        ingress_prog: &Program,
        egress_prog: &Program,
    ) -> LdEbpfResult<()> {
        register_stage(
            &self.inner.skel.maps.ingress_stage_progs,
            INGRESS_STAGE_FIREWALL,
            ingress_prog,
        )?;
        register_stage(
            &self.inner.skel.maps.egress_stage_progs,
            EGRESS_STAGE_FIREWALL,
            egress_prog,
        )?;
        Ok(())
    }

    pub fn unregister_firewall(&self) {
        let _ =
            self.inner.skel.maps.ingress_stage_progs.delete(&INGRESS_STAGE_FIREWALL.to_ne_bytes());
        let _ =
            self.inner.skel.maps.egress_stage_progs.delete(&EGRESS_STAGE_FIREWALL.to_ne_bytes());
    }

    pub fn register_mss(&self, ingress_prog: &Program, egress_prog: &Program) -> LdEbpfResult<()> {
        register_stage(&self.inner.skel.maps.ingress_stage_progs, INGRESS_STAGE_MSS, ingress_prog)?;
        register_stage(&self.inner.skel.maps.egress_stage_progs, EGRESS_STAGE_MSS, egress_prog)?;
        Ok(())
    }

    pub fn unregister_mss(&self) {
        let _ = self.inner.skel.maps.ingress_stage_progs.delete(&INGRESS_STAGE_MSS.to_ne_bytes());
        let _ = self.inner.skel.maps.egress_stage_progs.delete(&EGRESS_STAGE_MSS.to_ne_bytes());
    }
}

impl WanTcPipelineInner {
    fn new(ifindex: u32) -> LdEbpfResult<Self> {
        let builder = WanTcPipelineSkelBuilder::default();
        let (backing, open_object) = OwnedOpenObject::new();
        let mut open_skel =
            crate::bpf_ctx!(builder.open(open_object), "wan_tc_pipeline open skeleton failed")?;
        let ingress_path = wan_tc_pipeline_ingress_path(ifindex);
        let egress_path = wan_tc_pipeline_egress_path(ifindex);
        reuse_pinned_map_or_recreate(&mut open_skel.maps.ingress_stage_progs, &ingress_path);
        reuse_pinned_map_or_recreate(&mut open_skel.maps.egress_stage_progs, &egress_path);
        let skel = crate::bpf_ctx!(open_skel.load(), "wan_tc_pipeline load skeleton failed")?;
        clear_stage_slots(&skel.maps.ingress_stage_progs, INGRESS_STAGE_COUNT);
        clear_stage_slots(&skel.maps.egress_stage_progs, EGRESS_STAGE_COUNT);

        let mut ingress_hook = TcHookProxy::new(
            &skel.progs.wan_tc_pipeline_ingress_root,
            ifindex as i32,
            TC_INGRESS,
            WAN_ROUTE_INGRESS_PRIORITY,
        );
        let mut egress_hook = TcHookProxy::new(
            &skel.progs.wan_tc_pipeline_egress_root,
            ifindex as i32,
            TC_EGRESS,
            WAN_ROUTE_EGRESS_PRIORITY,
        );

        ingress_hook.attach();
        egress_hook.attach();

        Ok(Self {
            _backing: backing,
            skel,
            ingress_hook: Mutex::new(Some(ingress_hook)),
            egress_hook: Mutex::new(Some(egress_hook)),
            ifindex,
        })
    }
}

impl Drop for WanTcPipelineInner {
    fn drop(&mut self) {
        let mut pipelines = PIPELINES.lock().expect("wan tc pipeline registry poisoned");
        pipelines.remove(&self.ifindex);
        self.ingress_hook.lock().expect("wan tc pipeline ingress hook poisoned").take();
        self.egress_hook.lock().expect("wan tc pipeline egress hook poisoned").take();
    }
}

fn register_stage<M: MapCore>(map: &M, slot: u32, prog: &Program) -> LdEbpfResult<()> {
    let prog_fd = prog.as_fd().as_raw_fd();
    crate::bpf_ctx!(
        map.update(&slot.to_ne_bytes(), &prog_fd.to_ne_bytes(), MapFlags::ANY),
        "wan_tc_pipeline register stage {slot} failed"
    )?;
    Ok(())
}

fn clear_stage_slots<M: MapCore>(map: &M, count: u32) {
    for slot in 0..count {
        let _ = map.delete(&slot.to_ne_bytes());
    }
}
