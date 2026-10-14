use std::collections::{BTreeMap, HashMap};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};

use crate::LandscapeMapPath;
use crate::bpf_ctx;
use crate::bpf_error::{LandscapeEbpfError, LdEbpfResult};
use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};

pub(crate) mod tc_wan_ingress_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_route.skel.rs"));
}
mod tc_wan_egress_exit_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_exit.skel.rs"));
}
mod tc_wan_egress_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_root.skel.rs"));
}
mod tc_wan_ingress_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_root.skel.rs"));
}

use tc_wan_egress_exit_skel::TcWanEgressExitSkelBuilder;
use tc_wan_egress_root_skel::TcWanEgressRootSkelBuilder;
use tc_wan_ingress_root_skel::TcWanIngressRootSkelBuilder;
use tc_wan_ingress_route_skel::TcWanIngressRouteSkelBuilder;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StageType {
    Mss = 0,
    Firewall = 1,
    Nat4 = 2,
    Nat6 = 3,
    Pppoe = 4,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ChainDir {
    WanIngress,
    WanEgress,
}

fn update_prog_array_fd(map_fd: i32, key: u32, val: i32) -> LdEbpfResult<()> {
    let k = key.to_ne_bytes();
    let v = val.to_ne_bytes();
    let ret = unsafe {
        libbpf_sys::bpf_map_update_elem(
            map_fd,
            k.as_ptr() as *const std::ffi::c_void,
            v.as_ptr() as *const std::ffi::c_void,
            0,
        )
    };
    if ret != 0 {
        return Err(crate::bpf_error::LandscapeEbpfError::Context {
            context: format!("update_prog_array fd={} key={}", map_fd, key),
            source: libbpf_rs::Error::from_raw_os_error(-ret),
        });
    }
    Ok(())
}

fn delete_prog_array_fd(map_fd: i32, key: u32) {
    let k = key.to_ne_bytes();
    let _ =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, k.as_ptr() as *const std::ffi::c_void) };
}

/// Link one family's link_chain_id: root slot → the first entry, then each
/// entry's next-stage map to its successor. Entries with a zero family
/// program fd (family-partial stages, e.g. Nat4) never join this list.
fn link_family_chain(
    root_fd: i32,
    slot: u32,
    link_chain_id: &[&StageEntry],
    prog_fd: impl Fn(&StageEntry) -> i32,
    next_fd: impl Fn(&StageEntry) -> i32,
) -> LdEbpfResult<()> {
    let Some(first) = link_chain_id.first() else { return Ok(()) };
    update_prog_array_fd(root_fd, slot, prog_fd(first))?;
    for i in 0..link_chain_id.len() - 1 {
        update_prog_array_fd(next_fd(link_chain_id[i]), slot, prog_fd(link_chain_id[i + 1]))?;
    }
    Ok(())
}

// ── Pure Rust map creation (delete-if-exists then create + pin) ──

fn bpf_create_opts() -> libbpf_sys::bpf_map_create_opts {
    libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    }
}

fn create_pinned_prog_array(path: &Path, max_entries: u32) -> LdEbpfResult<()> {
    create_pinned_map(path, MapType::ProgArray, 4, 4, max_entries)
}

fn create_pinned_map(
    path: &Path,
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> LdEbpfResult<()> {
    let _ = std::fs::remove_file(path);
    let opts = bpf_create_opts();
    let name = path.file_name().and_then(|s| s.to_str());
    let mut map = MapHandle::create(map_type, name, key_size, value_size, max_entries, &opts)
        .map_err(|e| crate::bpf_error::LandscapeEbpfError::Context {
            context: format!("create map {}", path.display()),
            source: e,
        })?;
    map.pin(path.to_str().unwrap_or_default()).map_err(|e| {
        crate::bpf_error::LandscapeEbpfError::Context {
            context: format!("pin map {}", path.display()),
            source: e,
        }
    })?;
    Ok(())
}

fn pinned_map(path: &Path) -> LdEbpfResult<MapHandle> {
    MapHandle::from_pinned_path(path).map_err(|e| crate::bpf_error::LandscapeEbpfError::Context {
        context: format!("open pinned map {}", path.display()),
        source: e,
    })
}

struct IngressRoot {
    _skel: tc_wan_ingress_root_skel::TcWanIngressRootSkel<'static>,
    _backing: OwnedOpenObject,
    next_stage_fd: i32,
}

struct EgressRoot {
    _skel: tc_wan_egress_root_skel::TcWanEgressRootSkel<'static>,
    _backing: OwnedOpenObject,
    next_stage_fd: i32,
}

pub struct StageEntry {
    pub wan_ingress_prog_v4_fd: i32,
    pub wan_ingress_prog_v6_fd: i32,
    pub wan_egress_prog_v4_fd: i32,
    pub wan_egress_prog_v6_fd: i32,
    pub wan_ingress_next_stage_fd: i32,
    pub wan_egress_next_stage_fd: i32,
}

// Family-indexed link_chain_id slots; must match TC_SLOT_V4/TC_SLOT_V6 in tc_cb.h.
const TC_SLOT_V4: u32 = 0;
const TC_SLOT_V6: u32 = 1;

#[derive(Default)]
struct ChainState {
    ingress_root: Option<IngressRoot>,
    egress_root: Option<EgressRoot>,
    stages: BTreeMap<StageType, StageEntry>,
    has_eth_header: bool,
}

struct ManagerInner {
    // WAN-link chains, keyed by the owning link's link id.
    chains: HashMap<u16, ChainState>,
}

impl ManagerInner {
    fn new() -> Self {
        Self { chains: HashMap::new() }
    }
}

pub struct TcChainManager {
    paths: Arc<LandscapeMapPath>,
    _route_wi: tc_wan_ingress_route_skel::TcWanIngressRouteSkel<'static>,
    _exit_we: tc_wan_egress_exit_skel::TcWanEgressExitSkel<'static>,
    _back_wi: OwnedOpenObject,
    _back_we: OwnedOpenObject,
    inner: Mutex<ManagerInner>,
}

impl TcChainManager {
    /// Create the TC link_chain_id pin directory, seed its prog-array maps and load
    /// the shared terminal skeletons: the WAN ingress route unit and the WAN
    /// egress exit.
    pub fn new(paths: Arc<LandscapeMapPath>) -> LdEbpfResult<Self> {
        let tc_chain_base = paths.tc_chain_base();
        std::fs::create_dir_all(&tc_chain_base).map_err(|e| LandscapeEbpfError::Context {
            context: format!("can not create tc chain dir {}", tc_chain_base.display()),
            source: e.into(),
        })?;

        // Legacy pin of the pre-trie dispatch hash map: nothing reads it
        // anymore, so reclaim the bpffs entry if a previous run left one.
        let _ = std::fs::remove_file(tc_chain_base.join("wan_intro_dispatch"));

        // ── 1. Create and pin all seed PROG_ARRAY / HASH maps directly in Rust ──

        create_pinned_prog_array(&paths.tc_pipe_root_progs_path(), 1024)?;
        create_pinned_prog_array(&paths.tc_pipe_exits_wan_ingress_path(), 1)?;
        create_pinned_prog_array(&paths.tc_pipe_exits_wan_egress_path(), 1)?;
        create_pinned_prog_array(&paths.tc_wan_egress_roots_path(), 1024)?;

        // ── 2. Load exit skeletons and inject their program FDs ──

        let (route_wi, back_wi) = Self::init_wan_ingress_route(&paths)?;
        let (exit_we, back_we) = Self::init_exit_wan_egress(&paths)?;

        Ok(Self {
            paths,
            _route_wi: route_wi,
            _exit_we: exit_we,
            _back_wi: back_wi,
            _back_we: back_we,
            inner: Mutex::new(ManagerInner::new()),
        })
    }

    fn init_wan_ingress_route(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(tc_wan_ingress_route_skel::TcWanIngressRouteSkel<'static>, OwnedOpenObject)>
    {
        let builder = TcWanIngressRouteSkelBuilder::default();
        let (back, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_wan_ingress_route skeleton")?;
        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.tc_pipe_exits_wan_ingress,
            &paths.tc_pipe_exits_wan_ingress_path(),
        );
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
            "tc_wan_ingress_route pin flow_match_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &paths.wan_ip),
            "tc_wan_ingress_route pin wan_ip_binding"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
            "tc_wan_ingress_route pin rt4_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
            "tc_wan_ingress_route pin rt6_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_slot_map, &paths.rt4_slot_map,),
            "tc_wan_ingress_route pin rt4_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_slot_map, &paths.rt6_slot_map,),
            "tc_wan_ingress_route pin rt6_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
            "tc_wan_ingress_route pin flow4_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
            "tc_wan_ingress_route pin flow6_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
            "tc_wan_ingress_route pin flow4_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
            "tc_wan_ingress_route pin flow6_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
            "tc_wan_ingress_route pin rt4_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
            "tc_wan_ingress_route pin rt6_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
            "tc_wan_ingress_route pin ip_mac_v4"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
            "tc_wan_ingress_route pin ip_mac_v6"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able),
            "tc_wan_ingress_route pin xdp_redirect_able"
        )?;
        let skel = bpf_ctx!(open_skel.load(), "load tc_wan_ingress_route skeleton")?;
        let route_fd = skel.progs.tc_wan_ingress_route.as_fd().as_raw_fd();
        skel.maps.tc_pipe_exits_wan_ingress.update(
            &0u32.to_ne_bytes(),
            &route_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok((skel, back))
    }

    fn init_exit_wan_egress(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(tc_wan_egress_exit_skel::TcWanEgressExitSkel<'static>, OwnedOpenObject)>
    {
        let builder = TcWanEgressExitSkelBuilder::default();
        let (back, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_wan_egress_exit skeleton")?;
        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.tc_pipe_exits_wan_egress,
            &paths.tc_pipe_exits_wan_egress_path(),
        );
        let skel = bpf_ctx!(open_skel.load(), "load tc_wan_egress_exit skeleton")?;
        let exit_fd = skel.progs.tc_wan_egress_exit_redirect.as_fd().as_raw_fd();
        skel.maps.tc_pipe_exits_wan_egress.update(
            &0u32.to_ne_bytes(),
            &exit_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok((skel, back))
    }

    /// Ensure both direction link_chain_id roots of the WAN link owning `link_chain_id`
    /// exist (idempotent).  Called by the WAN link hub when the link comes
    /// up; `has_eth_header` (derived from the link iface's MAC presence)
    /// selects the L3 offset the roots operate with.
    pub fn ensure_roots(&self, link_chain_id: u16, has_eth_header: bool) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_roots_locked(&mut inner, link_chain_id, has_eth_header)
    }

    fn ensure_roots_locked(
        &self,
        inner: &mut ManagerInner,
        link_chain_id: u16,
        has_eth_header: bool,
    ) -> LdEbpfResult<()> {
        let state = inner.chains.entry(link_chain_id).or_default();
        state.has_eth_header = has_eth_header;
        let l3_offset: u32 = if has_eth_header { 14 } else { 0 };
        if state.ingress_root.is_none() {
            state.ingress_root = Some(self.create_ingress_root(link_chain_id, l3_offset)?);
        }
        if state.egress_root.is_none() {
            state.egress_root = Some(self.create_egress_root(link_chain_id, l3_offset)?);
        }
        Ok(())
    }

    fn create_ingress_root(&self, link_chain_id: u16, l3_offset: u32) -> LdEbpfResult<IngressRoot> {
        let ingress_builder = TcWanIngressRootSkelBuilder::default();
        let (ingress_back, ingress_obj) = OwnedOpenObject::new();
        let mut ingress_open_skel =
            bpf_ctx!(ingress_builder.open(ingress_obj), "open tc_wan_ingress_root")?;

        ingress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;
        ingress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_chain =
            link_chain_id as u32;

        pin_and_reuse_map(
            &mut ingress_open_skel.maps.tc_pipe_exits_wan_ingress,
            &self.paths.tc_pipe_exits_wan_ingress_path(),
        )?;

        let ingress_skel = bpf_ctx!(ingress_open_skel.load(), "load tc_wan_ingress_root")?;

        let ingress_root_fd = ingress_skel.progs.tc_wan_ingress_root.as_fd().as_raw_fd();
        let ing_next_fd = ingress_skel.maps.wan_ingress_root_next_stage.as_fd().as_raw_fd();

        pinned_map(&self.paths.tc_pipe_root_progs_path())?.update(
            &link_chain_id.to_ne_bytes(),
            &ingress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(IngressRoot {
            _skel: ingress_skel,
            _backing: ingress_back,
            next_stage_fd: ing_next_fd,
        })
    }

    fn create_egress_root(&self, link_chain_id: u16, l3_offset: u32) -> LdEbpfResult<EgressRoot> {
        let egress_builder = TcWanEgressRootSkelBuilder::default();
        let (egress_back, egress_obj) = OwnedOpenObject::new();
        let mut egress_open_skel =
            bpf_ctx!(egress_builder.open(egress_obj), "open tc_wan_egress_root")?;

        egress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;

        pin_and_reuse_map(
            &mut egress_open_skel.maps.tc_pipe_exits_wan_egress,
            &self.paths.tc_pipe_exits_wan_egress_path(),
        )?;

        let egress_skel = bpf_ctx!(egress_open_skel.load(), "load tc_wan_egress_root")?;

        let egress_root_fd = egress_skel.progs.tc_wan_egress_root.as_fd().as_raw_fd();
        let eg_next_fd = egress_skel.maps.wan_egress_root_next_stage.as_fd().as_raw_fd();

        pinned_map(&self.paths.tc_wan_egress_roots_path())?.update(
            &link_chain_id.to_ne_bytes(),
            &egress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(EgressRoot {
            _skel: egress_skel,
            _backing: egress_back,
            next_stage_fd: eg_next_fd,
        })
    }

    pub fn inject(
        &self,
        link_chain_id: u16,
        stage: StageType,
        entry: StageEntry,
    ) -> LdEbpfResult<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            let state = inner.chains.entry(link_chain_id).or_default();
            state.stages.insert(stage, entry);
        }
        self.rebuild(link_chain_id, ChainDir::WanIngress)?;
        self.rebuild(link_chain_id, ChainDir::WanEgress)?;
        Ok(())
    }

    /// Tear down the WAN link chain identified by `link_chain_id`: drop both
    /// direction roots and their prog-array slots.  Called by the hub at
    /// link teardown; stages still registered are discarded.
    pub fn remove_roots(&self, link_chain_id: u16) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(state) = inner.chains.remove(&link_chain_id) {
            if !state.stages.is_empty() {
                tracing::warn!(
                    "removing tc roots for link_chain_id={link_chain_id} with stages still registered ({})",
                    state.stages.len()
                );
            }
        } else {
            return;
        }

        if let Ok(map) = pinned_map(&self.paths.tc_pipe_root_progs_path()) {
            let _ = map.delete(&link_chain_id.to_ne_bytes());
        }
        if let Ok(map) = pinned_map(&self.paths.tc_wan_egress_roots_path()) {
            let _ = map.delete(&link_chain_id.to_ne_bytes());
        }
    }

    /// Remove one stage from both direction chains of `link_chain_id`.  The roots
    /// stay registered for the link's lifetime (the hub tears them down
    /// when the link goes away).
    pub fn remove(&self, link_chain_id: u16, stage: StageType) -> LdEbpfResult<()> {
        let has_state;
        {
            let mut inner = self.inner.lock().unwrap();
            has_state = inner
                .chains
                .get_mut(&link_chain_id)
                .is_some_and(|state| state.stages.remove(&stage).is_some());
        }
        if has_state {
            self.rebuild(link_chain_id, ChainDir::WanIngress)?;
            self.rebuild(link_chain_id, ChainDir::WanEgress)?;
        }
        Ok(())
    }

    fn rebuild(&self, link_chain_id: u16, dir: ChainDir) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();

        let has_eth_header =
            inner.chains.get(&link_chain_id).map(|s| s.has_eth_header).unwrap_or(false);
        self.ensure_roots_locked(&mut inner, link_chain_id, has_eth_header)?;

        let state = inner.chains.get_mut(&link_chain_id).unwrap();
        let root_next_stage_fd = match dir {
            ChainDir::WanIngress => state.ingress_root.as_ref().unwrap().next_stage_fd,
            ChainDir::WanEgress => state.egress_root.as_ref().unwrap().next_stage_fd,
        };

        for entry in state.stages.values() {
            let next_fd = match dir {
                ChainDir::WanIngress => entry.wan_ingress_next_stage_fd,
                ChainDir::WanEgress => entry.wan_egress_next_stage_fd,
            };
            if next_fd != 0 {
                delete_prog_array_fd(next_fd, TC_SLOT_V4);
                delete_prog_array_fd(next_fd, TC_SLOT_V6);
            }
        }
        delete_prog_array_fd(root_next_stage_fd, TC_SLOT_V4);
        delete_prog_array_fd(root_next_stage_fd, TC_SLOT_V6);

        let sorted_v4: Vec<&StageEntry> = state
            .stages
            .values()
            .filter(|v| match dir {
                ChainDir::WanIngress => v.wan_ingress_prog_v4_fd != 0,
                ChainDir::WanEgress => v.wan_egress_prog_v4_fd != 0,
            })
            .collect();
        let sorted_v6: Vec<&StageEntry> = state
            .stages
            .values()
            .filter(|v| match dir {
                ChainDir::WanIngress => v.wan_ingress_prog_v6_fd != 0,
                ChainDir::WanEgress => v.wan_egress_prog_v6_fd != 0,
            })
            .collect();

        type ProgFdFn = fn(&StageEntry) -> i32;
        let (prog_v4_fd, prog_v6_fd, next_stage_fd): (ProgFdFn, ProgFdFn, ProgFdFn) = match dir {
            ChainDir::WanIngress => (
                |e: &StageEntry| e.wan_ingress_prog_v4_fd,
                |e: &StageEntry| e.wan_ingress_prog_v6_fd,
                |e: &StageEntry| e.wan_ingress_next_stage_fd,
            ),
            ChainDir::WanEgress => (
                |e: &StageEntry| e.wan_egress_prog_v4_fd,
                |e: &StageEntry| e.wan_egress_prog_v6_fd,
                |e: &StageEntry| e.wan_egress_next_stage_fd,
            ),
        };

        link_family_chain(root_next_stage_fd, TC_SLOT_V4, &sorted_v4, prog_v4_fd, next_stage_fd)?;
        link_family_chain(root_next_stage_fd, TC_SLOT_V6, &sorted_v6, prog_v6_fd, next_stage_fd)?;

        Ok(())
    }
}
