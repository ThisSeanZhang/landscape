use std::collections::{BTreeMap, HashMap};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};

use landscape_common::args::LAND_ARGS;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::MAP_PATHS;

mod tc_exit_wan_ingress_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_exit_wan_ingress.skel.rs"));
}
mod tc_exit_wan_egress_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_exit_wan_egress.skel.rs"));
}
mod tc_wan_egress_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_root.skel.rs"));
}
mod tc_wan_ingress_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_root.skel.rs"));
}

use tc_exit_wan_egress_skel::TcExitWanEgressSkelBuilder;
use tc_exit_wan_ingress_skel::TcExitWanIngressSkelBuilder;
use tc_wan_egress_root_skel::TcWanEgressRootSkelBuilder;
use tc_wan_ingress_root_skel::TcWanIngressRootSkelBuilder;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StageType {
    Mss = 0,
    Firewall = 1,
    Nat = 2,
    Pppoe = 3,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ChainDir {
    WanIngress,
    WanEgress,
}

pub(crate) fn tc_chain_base() -> PathBuf {
    PathBuf::from(format!("/sys/fs/bpf/landscape/{}/tc_chain", LAND_ARGS.ebpf_map_space))
}

pub(crate) fn tc_pipe_root_progs_path() -> PathBuf {
    tc_chain_base().join("tc_pipe_root_progs")
}

pub(crate) fn wan_intro_dispatch_path() -> PathBuf {
    tc_chain_base().join("wan_intro_dispatch")
}

pub(crate) fn tc_pipe_exits_wan_ingress_path() -> PathBuf {
    tc_chain_base().join("tc_pipe_exits_wan_ingress")
}

pub(crate) fn tc_pipe_exits_wan_egress_path() -> PathBuf {
    tc_chain_base().join("tc_pipe_exits_wan_egress")
}

pub(crate) fn tc_wan_egress_roots_path() -> PathBuf {
    tc_chain_base().join("tc_wan_egress_roots")
}

const TC_INTRO_IFINDEX_TYPE: u32 = 2;

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
    pub wan_ingress_prog_fd: i32,
    pub wan_egress_prog_fd: i32,
    pub wan_ingress_next_stage_fd: i32,
    pub wan_egress_next_stage_fd: i32,
}

struct IfState {
    ingress_root: Option<IngressRoot>,
    egress_root: Option<EgressRoot>,
    stages: BTreeMap<StageType, StageEntry>,
    has_mac: bool,
}

impl Default for IfState {
    fn default() -> Self {
        Self {
            ingress_root: None,
            egress_root: None,
            stages: BTreeMap::new(),
            has_mac: false,
        }
    }
}

struct ManagerInner {
    interfaces: HashMap<u32, IfState>,
}

impl ManagerInner {
    fn new() -> Self {
        Self { interfaces: HashMap::new() }
    }
}

pub struct TcChainManager {
    _exit_wi: tc_exit_wan_ingress_skel::TcExitWanIngressSkel<'static>,
    _exit_we: tc_exit_wan_egress_skel::TcExitWanEgressSkel<'static>,
    _back_wi: OwnedOpenObject,
    _back_we: OwnedOpenObject,
    inner: Mutex<ManagerInner>,
}

static MANAGER: OnceLock<TcChainManager> = OnceLock::new();

impl TcChainManager {
    pub fn instance() -> &'static Self {
        MANAGER.get_or_init(|| Self::init().expect("TC chain manager init failed"))
    }

    fn init() -> LdEbpfResult<Self> {
        std::fs::create_dir_all(tc_chain_base()).expect("create tc_chain dir failed");

        // ── 1. Create and pin all seed PROG_ARRAY / HASH maps directly in Rust ──

        create_pinned_prog_array(&tc_pipe_root_progs_path(), 1024)?;
        create_pinned_map(&wan_intro_dispatch_path(), MapType::Hash, 16, 4, 1024)?;
        create_pinned_prog_array(&tc_pipe_exits_wan_ingress_path(), 1)?;
        create_pinned_prog_array(&tc_pipe_exits_wan_egress_path(), 1)?;
        create_pinned_prog_array(&tc_wan_egress_roots_path(), 1024)?;

        // ── 2. Load exit skeletons and inject their program FDs ──

        let (exit_wi, back_wi) = Self::init_exit_wan_ingress()?;
        let (exit_we, back_we) = Self::init_exit_wan_egress()?;

        Ok(Self {
            _exit_wi: exit_wi,
            _exit_we: exit_we,
            _back_wi: back_wi,
            _back_we: back_we,
            inner: Mutex::new(ManagerInner::new()),
        })
    }

    fn init_exit_wan_ingress(
    ) -> LdEbpfResult<(tc_exit_wan_ingress_skel::TcExitWanIngressSkel<'static>, OwnedOpenObject)>
    {
        let builder = TcExitWanIngressSkelBuilder::default();
        let (back, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_exit_wan_ingress skeleton")?;
        crate::map_setting::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.tc_pipe_exits_wan_ingress,
            &tc_pipe_exits_wan_ingress_path(),
        );
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &MAP_PATHS.flow_match_map),
            "tc_exit_wan_ingress pin flow_match_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &MAP_PATHS.wan_ip),
            "tc_exit_wan_ingress pin wan_ip_binding"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &MAP_PATHS.rt4_lan_map),
            "tc_exit_wan_ingress pin rt4_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &MAP_PATHS.rt6_lan_map),
            "tc_exit_wan_ingress pin rt6_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(
                &mut open_skel.maps.rt4_target_slot_map,
                &MAP_PATHS.rt4_target_slot_map,
            ),
            "tc_exit_wan_ingress pin rt4_target_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(
                &mut open_skel.maps.rt6_target_slot_map,
                &MAP_PATHS.rt6_target_slot_map,
            ),
            "tc_exit_wan_ingress pin rt6_target_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &MAP_PATHS.flow4_dns_map),
            "tc_exit_wan_ingress pin flow4_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &MAP_PATHS.flow6_dns_map),
            "tc_exit_wan_ingress pin flow6_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &MAP_PATHS.flow4_ip_map),
            "tc_exit_wan_ingress pin flow4_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &MAP_PATHS.flow6_ip_map),
            "tc_exit_wan_ingress pin flow6_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &MAP_PATHS.rt4_cache_map),
            "tc_exit_wan_ingress pin rt4_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &MAP_PATHS.rt6_cache_map),
            "tc_exit_wan_ingress pin rt6_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &MAP_PATHS.ip_mac_v4),
            "tc_exit_wan_ingress pin ip_mac_v4"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &MAP_PATHS.ip_mac_v6),
            "tc_exit_wan_ingress pin ip_mac_v6"
        )?;
        let skel = bpf_ctx!(open_skel.load(), "load tc_exit_wan_ingress skeleton")?;
        let exit_fd = skel.progs.tc_exit_wan_ingress_redirect.as_fd().as_raw_fd();
        skel.maps.tc_pipe_exits_wan_ingress.update(
            &0u32.to_ne_bytes(),
            &exit_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok((skel, back))
    }

    fn init_exit_wan_egress(
    ) -> LdEbpfResult<(tc_exit_wan_egress_skel::TcExitWanEgressSkel<'static>, OwnedOpenObject)>
    {
        let builder = TcExitWanEgressSkelBuilder::default();
        let (back, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_exit_wan_egress skeleton")?;
        crate::map_setting::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.tc_pipe_exits_wan_egress,
            &tc_pipe_exits_wan_egress_path(),
        );
        let skel = bpf_ctx!(open_skel.load(), "load tc_exit_wan_egress skeleton")?;
        let exit_fd = skel.progs.tc_exit_wan_egress_redirect.as_fd().as_raw_fd();
        skel.maps.tc_pipe_exits_wan_egress.update(
            &0u32.to_ne_bytes(),
            &exit_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok((skel, back))
    }

    pub fn ensure_roots(&self, ifindex: u32, has_mac: bool) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_roots_locked(&mut inner, ifindex, has_mac)
    }

    fn ensure_roots_locked(
        &self,
        inner: &mut ManagerInner,
        ifindex: u32,
        has_mac: bool,
    ) -> LdEbpfResult<()> {
        let state = inner.interfaces.entry(ifindex).or_default();
        state.has_mac = has_mac;
        let l3_offset: u32 = if has_mac { 14 } else { 0 };
        if state.ingress_root.is_none() {
            state.ingress_root = Some(self.create_ingress_root(ifindex, l3_offset)?);
        }
        if state.egress_root.is_none() {
            state.egress_root = Some(self.create_egress_roots(ifindex)?);
        }
        Ok(())
    }

    fn create_ingress_root(&self, ifindex: u32, l3_offset: u32) -> LdEbpfResult<IngressRoot> {
        let ingress_builder = TcWanIngressRootSkelBuilder::default();
        let (ingress_back, ingress_obj) = OwnedOpenObject::new();
        let mut ingress_open_skel =
            bpf_ctx!(ingress_builder.open(ingress_obj), "open tc_wan_ingress_root")?;

        ingress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;

        pin_and_reuse_map(
            &mut ingress_open_skel.maps.tc_pipe_exits_wan_ingress,
            &tc_pipe_exits_wan_ingress_path(),
        )?;

        let ingress_skel = bpf_ctx!(ingress_open_skel.load(), "load tc_wan_ingress_root")?;

        let ingress_root_fd = ingress_skel.progs.tc_wan_chain_ingress_root.as_fd().as_raw_fd();
        let ing_next_fd = ingress_skel.maps.wan_ingress_root_next_stage.as_fd().as_raw_fd();

        pinned_map(&tc_pipe_root_progs_path())?.update(
            &ifindex.to_ne_bytes(),
            &ingress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&TC_INTRO_IFINDEX_TYPE.to_le_bytes());
        dispatch_key[8..12].copy_from_slice(&ifindex.to_le_bytes());
        let dispatch_val = ifindex.to_ne_bytes();
        pinned_map(&wan_intro_dispatch_path())?.update(
            &dispatch_key,
            &dispatch_val,
            MapFlags::ANY,
        )?;

        Ok(IngressRoot {
            _skel: ingress_skel,
            _backing: ingress_back,
            next_stage_fd: ing_next_fd,
        })
    }

    fn create_egress_roots(&self, ifindex: u32) -> LdEbpfResult<EgressRoot> {
        let egress_builder = TcWanEgressRootSkelBuilder::default();
        let (egress_back, egress_obj) = OwnedOpenObject::new();
        let mut egress_open_skel =
            bpf_ctx!(egress_builder.open(egress_obj), "open tc_wan_egress_root")?;

        pin_and_reuse_map(
            &mut egress_open_skel.maps.tc_pipe_exits_wan_egress,
            &tc_pipe_exits_wan_egress_path(),
        )?;

        let egress_skel = bpf_ctx!(egress_open_skel.load(), "load tc_wan_egress_root")?;

        let egress_root_fd = egress_skel.progs.tc_wan_chain_egress_root.as_fd().as_raw_fd();
        let eg_next_fd = egress_skel.maps.wan_egress_root_next_stage.as_fd().as_raw_fd();

        pinned_map(&tc_wan_egress_roots_path())?.update(
            &ifindex.to_ne_bytes(),
            &egress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(EgressRoot {
            _skel: egress_skel,
            _backing: egress_back,
            next_stage_fd: eg_next_fd,
        })
    }

    pub fn inject(&self, ifindex: u32, stage: StageType, entry: StageEntry) -> LdEbpfResult<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            let state = inner.interfaces.entry(ifindex).or_default();
            state.stages.insert(stage, entry);
        }
        self.rebuild(ifindex, ChainDir::WanIngress)?;
        self.rebuild(ifindex, ChainDir::WanEgress)?;
        Ok(())
    }

    pub fn remove_roots(&self, ifindex: u32) {
        let mut inner = self.inner.lock().unwrap();
        if inner.interfaces.remove(&ifindex).is_none() {
            return;
        }

        if let Ok(map) = pinned_map(&tc_pipe_root_progs_path()) {
            let _ = map.delete(&ifindex.to_ne_bytes());
        }
        if let Ok(map) = pinned_map(&tc_wan_egress_roots_path()) {
            let _ = map.delete(&ifindex.to_ne_bytes());
        }

        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&TC_INTRO_IFINDEX_TYPE.to_le_bytes());
        dispatch_key[8..12].copy_from_slice(&ifindex.to_le_bytes());
        if let Ok(map) = pinned_map(&wan_intro_dispatch_path()) {
            let _ = map.delete(&dispatch_key);
        }
    }

    pub fn remove(&self, ifindex: u32, stage: StageType) -> LdEbpfResult<()> {
        let empty;
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(state) = inner.interfaces.get_mut(&ifindex) {
                state.stages.remove(&stage);
                empty = state.stages.is_empty();
            } else {
                return Ok(());
            }
        }
        if empty {
            self.remove_roots(ifindex);
        } else {
            self.rebuild(ifindex, ChainDir::WanIngress)?;
            self.rebuild(ifindex, ChainDir::WanEgress)?;
        }
        Ok(())
    }

    fn rebuild(&self, ifindex: u32, chain: ChainDir) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();

        if matches!(chain, ChainDir::WanIngress)
            && !inner.interfaces.get(&ifindex).and_then(|s| s.ingress_root.as_ref()).is_some()
        {
            return Ok(());
        }

        let has_mac = inner.interfaces.get(&ifindex).map(|s| s.has_mac).unwrap_or(false);

        {
            let state = inner.interfaces.entry(ifindex).or_default();
            state.has_mac = has_mac;
            match chain {
                ChainDir::WanIngress => {
                    if state.ingress_root.is_none() {
                        let l3_offset: u32 = if has_mac { 14 } else { 0 };
                        state.ingress_root = Some(self.create_ingress_root(ifindex, l3_offset)?);
                    }
                    if state.egress_root.is_none() {
                        state.egress_root = Some(self.create_egress_roots(ifindex)?);
                    }
                }
                ChainDir::WanEgress => {
                    if state.egress_root.is_none() {
                        state.egress_root = Some(self.create_egress_roots(ifindex)?);
                    }
                }
            }
        }

        let state = inner.interfaces.get_mut(&ifindex).unwrap();
        let root_next_stage_fd = match chain {
            ChainDir::WanIngress => state.ingress_root.as_ref().unwrap().next_stage_fd,
            ChainDir::WanEgress => state.egress_root.as_ref().unwrap().next_stage_fd,
        };

        for (_, entry) in &state.stages {
            let next_fd = match chain {
                ChainDir::WanIngress => entry.wan_ingress_next_stage_fd,
                ChainDir::WanEgress => entry.wan_egress_next_stage_fd,
            };
            if next_fd != 0 {
                delete_prog_array_fd(next_fd, 0);
            }
        }
        delete_prog_array_fd(root_next_stage_fd, 0);

        let sorted: Vec<&StageEntry> = state
            .stages
            .iter()
            .filter(|(k, _)| !matches!((k, chain), (StageType::Pppoe, ChainDir::WanIngress)))
            .map(|(_, v)| v)
            .filter(|v| match chain {
                ChainDir::WanIngress => v.wan_ingress_prog_fd != 0,
                ChainDir::WanEgress => v.wan_egress_prog_fd != 0,
            })
            .collect();
        if sorted.is_empty() {
            return Ok(());
        }

        let first_prog_fd = match chain {
            ChainDir::WanIngress => sorted[0].wan_ingress_prog_fd,
            ChainDir::WanEgress => sorted[0].wan_egress_prog_fd,
        };
        update_prog_array_fd(root_next_stage_fd, 0, first_prog_fd)?;

        for i in 0..sorted.len().saturating_sub(1) {
            let next_fd = match chain {
                ChainDir::WanIngress => sorted[i].wan_ingress_next_stage_fd,
                ChainDir::WanEgress => sorted[i].wan_egress_next_stage_fd,
            };
            let next_prog_fd = match chain {
                ChainDir::WanIngress => sorted[i + 1].wan_ingress_prog_fd,
                ChainDir::WanEgress => sorted[i + 1].wan_egress_prog_fd,
            };
            update_prog_array_fd(next_fd, 0, next_prog_fd)?;
        }

        Ok(())
    }
}
