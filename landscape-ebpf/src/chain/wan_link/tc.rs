//! TC half of the per-link chain: WAN-ingress / WAN-egress root
//! programs, per-direction stage tables, and the loader-facing view
//! ([`TcChainView`]) used by the TC stage loaders.

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::stage::FamilyProg;
use crate::chain::stage::FromLanStageType;
use crate::chain::stage::FromWanStageType;
use crate::chain::stage::StageFamily;
use crate::chain::stage::StageTable;
use crate::chain::stage::relink_family_stages;
use crate::landscape::OwnedOpenObject;
use crate::landscape::pin_and_reuse_map;
use crate::route_backbone::RouteBackbone;
use crate::route_backbone::pinned_map;

use super::WanLinkDataplane;

use crate::skel::tc_wan_egress_root::TcWanEgressRootSkelBuilder;
use crate::skel::tc_wan_ingress_root::TcWanIngressRootSkelBuilder;

// ── TC half ──

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TcChainDir {
    WanIngress,
    WanEgress,
}

pub(super) struct IngressRoot {
    _skel: crate::skel::tc_wan_ingress_root::TcWanIngressRootSkel<'static>,
    _backing: OwnedOpenObject,
    next_stage_fd: i32,
}

pub(super) struct EgressRoot {
    _skel: crate::skel::tc_wan_egress_root::TcWanEgressRootSkel<'static>,
    _backing: OwnedOpenObject,
    next_stage_fd: i32,
}

// Family-indexed link_chain_id slots; must match TC_SLOT_V4/TC_SLOT_V6 in tc_cb.h.
const TC_SLOT_V4: u32 = 0;
const TC_SLOT_V6: u32 = 1;

#[derive(Default)]

pub(super) struct TcChainState {
    pub(super) ingress_root: Option<IngressRoot>,
    pub(super) egress_root: Option<EgressRoot>,
    pub(super) ingress_stages: StageTable<FromWanStageType>,
    pub(super) egress_stages: StageTable<FromLanStageType>,
}

impl WanLinkDataplane {
    fn relink_tc(&self, dir: TcChainDir) -> LdEbpfResult<()> {
        let inner = self.inner.lock().unwrap();
        if inner.closed {
            tracing::warn!(chain = self.id, "relink on closed wan link dataplane");
            return Ok(());
        }
        let state = &inner.tc;
        match dir {
            TcChainDir::WanIngress => relink_family_stages(
                state.ingress_root.as_ref().unwrap().next_stage_fd,
                &state.ingress_stages,
                TC_SLOT_V4,
                TC_SLOT_V6,
                TC_SLOT_V4,
                TC_SLOT_V6,
            ),
            TcChainDir::WanEgress => relink_family_stages(
                state.egress_root.as_ref().unwrap().next_stage_fd,
                &state.egress_stages,
                TC_SLOT_V4,
                TC_SLOT_V6,
                TC_SLOT_V4,
                TC_SLOT_V6,
            ),
        }
    }

    pub(super) fn create_ingress_root(
        backbone: &RouteBackbone,
        link_chain_id: u16,
        l3_offset: u32,
    ) -> LdEbpfResult<IngressRoot> {
        let ingress_builder = TcWanIngressRootSkelBuilder::default();
        let (ingress_back, ingress_obj) = OwnedOpenObject::new();
        let mut ingress_open_skel =
            bpf_ctx!(ingress_builder.open(ingress_obj), "open tc_wan_ingress_root")?;

        // chain cb hard limits: l3 lives in 8 bits, chain id in 16.
        assert!(l3_offset <= u8::MAX as u32, "l3 offset {l3_offset} exceeds cb slot");

        ingress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
        ingress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_chain =
            link_chain_id as u32;

        pin_and_reuse_map(
            &mut ingress_open_skel.maps.tc_pipe_exits_wan_ingress,
            &backbone.paths().tc_pipe_exits_wan_ingress_path(),
        )?;
        // frag*_cache_* are no longer referenced by the roots: maps::init_path
        // recreates/pins them at startup and the NAT stage loaders reuse them.
        let ingress_skel = bpf_ctx!(ingress_open_skel.load(), "load tc_wan_ingress_root")?;

        let ingress_root_fd = ingress_skel.progs.tc_wan_ingress_root.as_fd().as_raw_fd();
        let ing_next_fd = ingress_skel.maps.wan_ingress_root_next_stage.as_fd().as_raw_fd();

        let slot_key = (link_chain_id as u32).to_ne_bytes();
        pinned_map(&backbone.paths().tc_pipe_root_progs_path())?.update(
            &slot_key,
            &ingress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(IngressRoot {
            _skel: ingress_skel,
            _backing: ingress_back,
            next_stage_fd: ing_next_fd,
        })
    }

    pub(super) fn create_egress_root(
        backbone: &RouteBackbone,
        link_chain_id: u16,
        l3_offset: u32,
    ) -> LdEbpfResult<EgressRoot> {
        let egress_builder = TcWanEgressRootSkelBuilder::default();
        let (egress_back, egress_obj) = OwnedOpenObject::new();
        let mut egress_open_skel =
            bpf_ctx!(egress_builder.open(egress_obj), "open tc_wan_egress_root")?;

        // chain cb hard limit: l3 lives in 8 bits.
        assert!(l3_offset <= u8::MAX as u32, "l3 offset {l3_offset} exceeds cb slot");

        egress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;

        pin_and_reuse_map(
            &mut egress_open_skel.maps.tc_pipe_exits_wan_egress,
            &backbone.paths().tc_pipe_exits_wan_egress_path(),
        )?;
        // See create_ingress_root: frag caches are initialized once by maps::init_path.
        let egress_skel = bpf_ctx!(egress_open_skel.load(), "load tc_wan_egress_root")?;

        let egress_root_fd = egress_skel.progs.tc_wan_egress_root.as_fd().as_raw_fd();
        let eg_next_fd = egress_skel.maps.wan_egress_root_next_stage.as_fd().as_raw_fd();

        let slot_key = (link_chain_id as u32).to_ne_bytes();
        pinned_map(&backbone.paths().tc_wan_egress_roots_path())?.update(
            &slot_key,
            &egress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(EgressRoot {
            _skel: egress_skel,
            _backing: egress_back,
            next_stage_fd: eg_next_fd,
        })
    }
}

/// TC-side view used by the stage loaders.
pub(crate) struct TcChainView<'a> {
    dp: &'a WanLinkDataplane,
}

impl<'a> TcChainView<'a> {
    pub(super) fn new(dp: &'a WanLinkDataplane) -> Self {
        Self { dp }
    }
}

impl TcChainView<'_> {
    pub(crate) fn inject_from_wan(
        &self,
        stage: FromWanStageType,
        family: StageFamily,
        prog: FamilyProg,
    ) -> LdEbpfResult<()> {
        if !self.dp.guard_open() {
            return Ok(());
        }
        let mut inner = self.dp.inner.lock().unwrap();
        inner.tc.ingress_stages.insert((stage, family), prog);
        drop(inner);
        self.dp.relink_tc(TcChainDir::WanIngress)
    }

    pub(crate) fn inject_from_lan(
        &self,
        stage: FromLanStageType,
        family: StageFamily,
        prog: FamilyProg,
    ) -> LdEbpfResult<()> {
        if !self.dp.guard_open() {
            return Ok(());
        }
        let mut inner = self.dp.inner.lock().unwrap();
        inner.tc.egress_stages.insert((stage, family), prog);
        drop(inner);
        self.dp.relink_tc(TcChainDir::WanEgress)
    }

    pub(crate) fn remove_from_wan(&self, stage: FromWanStageType, family: StageFamily) {
        if !self.dp.guard_open() {
            return;
        }
        let removed = {
            let mut inner = self.dp.inner.lock().unwrap();
            inner.tc.ingress_stages.remove(&(stage, family)).is_some()
        };
        if removed {
            let _ = self.dp.relink_tc(TcChainDir::WanIngress);
        }
    }

    pub(crate) fn remove_from_lan(&self, stage: FromLanStageType, family: StageFamily) {
        if !self.dp.guard_open() {
            return;
        }
        let removed = {
            let mut inner = self.dp.inner.lock().unwrap();
            inner.tc.egress_stages.remove(&(stage, family)).is_some()
        };
        if removed {
            let _ = self.dp.relink_tc(TcChainDir::WanEgress);
        }
    }
}
