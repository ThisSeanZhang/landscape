//! TC half of the per-link chain: WAN-ingress / WAN-egress root
//! programs, per-direction stage tables, and the loader-facing view
//! ([`TcChainView`]) used by the TC stage loaders.

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicU64, Ordering};

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
use crate::route_backbone::create_prog_array_map;
use crate::route_backbone::pinned_map;

use super::WanLinkDataplane;
use super::from_lan::WanEgressBinding;
use super::gateway_arp::GatewayArpState;

use crate::skel::tc_wan_egress_ppp_root::TcWanEgressPppRootSkelBuilder;
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

pub(super) enum EgressRoot {
    L2 {
        skel: crate::skel::tc_wan_egress_root::TcWanEgressRootSkel<'static>,
        _backing: OwnedOpenObject,
    },
    Ppp {
        skel: crate::skel::tc_wan_egress_ppp_root::TcWanEgressPppRootSkel<'static>,
        _backing: OwnedOpenObject,
    },
}

impl EgressRoot {
    pub(super) fn prog_fd(&self) -> i32 {
        match self {
            Self::L2 { skel, .. } => skel.progs.tc_wan_egress_root.as_fd().as_raw_fd(),
            Self::Ppp { skel, .. } => skel.progs.tc_wan_egress_ppp_root.as_fd().as_raw_fd(),
        }
    }

    pub(super) fn next_stage_map(&self) -> &libbpf_rs::MapMut<'static> {
        match self {
            Self::L2 { skel, .. } => &skel.maps.wan_egress_root_next_stage,
            Self::Ppp { skel, .. } => &skel.maps.wan_egress_root_next_stage,
        }
    }

    pub(super) fn sync_gateway_mac(&mut self, arp: &GatewayArpState) {
        let Self::L2 { skel, .. } = self else {
            return;
        };
        // A failed binding rebuild can leave the previous root installed.
        // Pair the MAC with this root's actual interface and next hop.
        let binding = &skel.maps.rodata_data.as_ref().unwrap().egress_binding;
        let mut bytes = [0u8; 8];
        if let Some((target, mac)) = arp.active_confirmation()
            && binding.has_l2 != 0
            && binding.is_pppoe == 0
            && binding.ifindex == target.ifindex
            && binding.gateway_ip4 == u32::from_ne_bytes(target.gateway_ip.octets())
        {
            bytes[..6].copy_from_slice(&mac.octets());
        }
        let mut bytes6 = [0u8; 8];
        if let Some((target, mac)) = arp.active_confirmation6()
            && binding.has_l2 != 0
            && binding.is_pppoe == 0
            && binding.has_ipv6 != 0
            && binding.ifindex == target.ifindex
            && binding.gateway_ip6 == target.gateway_ip.octets()
        {
            bytes6[..6].copy_from_slice(&mac.octets());
        }
        let bss = skel.maps.bss_data.as_deref_mut().expect("TC egress root .bss");
        // The mmap lives with the skeleton. The BPF global is aligned to eight bytes
        // and each packet reads it in one load, so it cannot see a partial MAC.
        unsafe { AtomicU64::from_ptr(&raw mut bss.confirmed_gateway_mac) }
            .store(u64::from_ne_bytes(bytes), Ordering::Relaxed);
        unsafe { AtomicU64::from_ptr(&raw mut bss.confirmed_gateway_mac6) }
            .store(u64::from_ne_bytes(bytes6), Ordering::Relaxed);
    }
}

#[cfg(all(test, feature = "test-chain"))]
impl EgressRoot {
    pub(super) fn l2_skel(
        &self,
    ) -> Option<&crate::skel::tc_wan_egress_root::TcWanEgressRootSkel<'static>> {
        match self {
            Self::L2 { skel, .. } => Some(skel),
            Self::Ppp { .. } => None,
        }
    }

    pub(super) fn ppp_skel(
        &self,
    ) -> Option<&crate::skel::tc_wan_egress_ppp_root::TcWanEgressPppRootSkel<'static>> {
        match self {
            Self::Ppp { skel, .. } => Some(skel),
            Self::L2 { .. } => None,
        }
    }
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
    /// Load this chain's from-LAN TC exit program into an unpinned exit map.
    /// The PROG_ARRAY slot keeps the program alive after the skeleton drops.
    pub(super) fn create_tc_wan_egress_exit_map() -> LdEbpfResult<libbpf_rs::MapHandle> {
        let builder = crate::skel::tc_wan_egress_exit::TcWanEgressExitSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let open_skel = bpf_ctx!(builder.open(obj), "open tc_wan_egress_exit skeleton")?;
        let skel = bpf_ctx!(open_skel.load(), "load tc_wan_egress_exit skeleton")?;

        let map = create_prog_array_map("tc_from_lan_exit_map", 1)?;
        map.update(
            &0u32.to_ne_bytes(),
            &skel.progs.tc_wan_egress_exit_redirect.as_fd().as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )?;

        drop(skel);
        drop(backing);
        Ok(map)
    }

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
                state.egress_root.as_ref().unwrap().next_stage_map().as_fd().as_raw_fd(),
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

    pub(super) fn build_egress_root(
        backbone: &RouteBackbone,
        binding: &WanEgressBinding,
        previous: Option<&EgressRoot>,
        exit_map: BorrowedFd<'_>,
    ) -> LdEbpfResult<EgressRoot> {
        if binding.is_p2p && !binding.has_l2 {
            Self::build_ppp_egress_root(previous)
        } else {
            Self::build_l2_egress_root(backbone, binding, previous, exit_map)
        }
    }

    fn build_l2_egress_root(
        backbone: &RouteBackbone,
        binding: &WanEgressBinding,
        previous: Option<&EgressRoot>,
        exit_map: BorrowedFd<'_>,
    ) -> LdEbpfResult<EgressRoot> {
        let egress_builder = TcWanEgressRootSkelBuilder::default();
        let (egress_back, egress_obj) = OwnedOpenObject::new();
        let mut egress_open_skel =
            bpf_ctx!(egress_builder.open(egress_obj), "open tc_wan_egress_root")?;

        let rodata = egress_open_skel.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_l3_offset = if binding.has_l2 { 14 } else { 0 };
        rodata.egress_binding = crate::skel::tc_wan_egress_root::types::wan_egress_binding {
            ifindex: binding.ifindex,
            wan_ip4: binding.wan_ip4,
            wan_mask4: binding.wan_mask4,
            gateway_ip4: binding.gateway_ip4,
            source_mac: binding.source_mac,
            has_ipv4: u8::from(binding.has_ipv4),
            has_l2: u8::from(binding.has_l2),
            is_pppoe: u8::from(binding.is_pppoe),
            wan_ip6: binding.wan_ip6,
            wan_mask6: binding.wan_mask6,
            gateway_ip6: binding.gateway_ip6,
            has_ipv6: u8::from(binding.has_ipv6),
        };
        pin_and_reuse_map(&mut egress_open_skel.maps.ip_mac_v4, &backbone.paths().ip_mac_v4)?;
        if let Some(old) = previous {
            egress_open_skel
                .maps
                .wan_egress_root_next_stage
                .reuse_fd(old.next_stage_map().as_fd())?;
        }

        egress_open_skel.maps.tc_from_lan_exit_map.reuse_fd(exit_map)?;
        // See create_ingress_root: frag caches are initialized once by maps::init_path.
        let egress_skel = bpf_ctx!(egress_open_skel.load(), "load tc_wan_egress_root")?;

        Ok(EgressRoot::L2 { skel: egress_skel, _backing: egress_back })
    }

    fn build_ppp_egress_root(previous: Option<&EgressRoot>) -> LdEbpfResult<EgressRoot> {
        let egress_builder = TcWanEgressPppRootSkelBuilder::default();
        let (egress_back, egress_obj) = OwnedOpenObject::new();
        let mut egress_open_skel =
            bpf_ctx!(egress_builder.open(egress_obj), "open tc_wan_egress_ppp_root")?;

        if let Some(old) = previous {
            egress_open_skel
                .maps
                .wan_egress_root_next_stage
                .reuse_fd(old.next_stage_map().as_fd())?;
        }

        let egress_skel = bpf_ctx!(egress_open_skel.load(), "load tc_wan_egress_ppp_root")?;

        Ok(EgressRoot::Ppp { skel: egress_skel, _backing: egress_back })
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
