use std::collections::{BTreeMap, HashMap};
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags};

use landscape_common::args::LAND_ARGS;

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};

mod tc_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_intro.skel.rs"));
}
mod tc_exit_wan_ingress_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_exit_wan_ingress.skel.rs"));
}
mod tc_exit_wan_egress_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_exit_wan_egress.skel.rs"));
}
mod tc_exit_lan_ingress_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_exit_lan_ingress.skel.rs"));
}
mod tc_lan_ingress_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_chain.skel.rs"));
}
mod tc_wan_egress_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_chain.skel.rs"));
}
mod tc_wan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_chain.skel.rs"));
}
mod tc_lan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_chain.skel.rs"));
}

use tc_exit_lan_ingress_skel::TcExitLanIngressSkelBuilder;
use tc_exit_wan_egress_skel::TcExitWanEgressSkelBuilder;
use tc_exit_wan_ingress_skel::TcExitWanIngressSkelBuilder;
use tc_intro_skel::TcIntroSkelBuilder;
use tc_lan_chain_skel::TcLanChainSkelBuilder;
use tc_lan_ingress_chain_skel::TcLanIngressChainSkelBuilder;
use tc_wan_chain_skel::TcWanChainSkelBuilder;
use tc_wan_egress_chain_skel::TcWanEgressChainSkelBuilder;

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
    LanIngress,
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

pub(crate) fn tc_pipe_exits_lan_ingress_path() -> PathBuf {
    tc_chain_base().join("tc_pipe_exits_lan_ingress")
}

pub(crate) fn tc_lan_ingress_roots_path() -> PathBuf {
    tc_chain_base().join("tc_lan_ingress_roots")
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

struct TcRoots {
    _wan_chain_skel: tc_wan_chain_skel::TcWanChainSkel<'static>,
    _wan_chain_backing: OwnedOpenObject,
    wan_ingress_root_next_stage_fd: i32,
    wan_egress_root_next_stage_fd: i32,

    _lan_chain_skel: tc_lan_chain_skel::TcLanChainSkel<'static>,
    _lan_chain_backing: OwnedOpenObject,
    lan_ingress_root_next_stage_fd: i32,
}

pub struct StageEntry {
    pub wan_ingress_prog_fd: i32,
    pub wan_egress_prog_fd: i32,
    pub lan_ingress_prog_fd: i32,
    pub wan_ingress_next_stage_fd: i32,
    pub wan_egress_next_stage_fd: i32,
    pub lan_ingress_next_stage_fd: i32,
}

struct IfState {
    roots: Option<TcRoots>,
    stages: BTreeMap<StageType, StageEntry>,
}

impl Default for IfState {
    fn default() -> Self {
        Self { roots: None, stages: BTreeMap::new() }
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
    _seed: tc_intro_skel::TcIntroSkel<'static>,
    _exit_wi: tc_exit_wan_ingress_skel::TcExitWanIngressSkel<'static>,
    _exit_we: tc_exit_wan_egress_skel::TcExitWanEgressSkel<'static>,
    _exit_li: tc_exit_lan_ingress_skel::TcExitLanIngressSkel<'static>,
    _lan_ingress_chain: tc_lan_ingress_chain_skel::TcLanIngressChainSkel<'static>,
    _wan_egress_chain: tc_wan_egress_chain_skel::TcWanEgressChainSkel<'static>,
    _back1: OwnedOpenObject,
    _back2: OwnedOpenObject,
    _back3: OwnedOpenObject,
    _back4: OwnedOpenObject,
    _back5: OwnedOpenObject,
    _back6: OwnedOpenObject,
    inner: Mutex<ManagerInner>,
}

static MANAGER: OnceLock<TcChainManager> = OnceLock::new();

impl TcChainManager {
    pub fn instance() -> &'static Self {
        MANAGER.get_or_init(|| Self::init().expect("TC chain manager init failed"))
    }

    fn init() -> LdEbpfResult<Self> {
        std::fs::create_dir_all(tc_chain_base()).expect("create tc_chain dir failed");

        // 1. tc_intro — tc_pipe_root_progs + wan_intro_dispatch_map
        let (back1, seed) = {
            let builder = TcIntroSkelBuilder::default();
            let (back, obj) = OwnedOpenObject::new();
            let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_intro skeleton")?;
            crate::map_setting::reuse_pinned_map_or_recreate(
                &mut open_skel.maps.tc_pipe_root_progs,
                &tc_pipe_root_progs_path(),
            );
            crate::map_setting::reuse_pinned_map_or_recreate(
                &mut open_skel.maps.wan_intro_dispatch_map,
                &wan_intro_dispatch_path(),
            );
            let skel = bpf_ctx!(open_skel.load(), "load tc_intro skeleton")?;
            (back, skel)
        };

        // 2. tc_exit_wan_ingress — tc_pipe_exits_wan_ingress
        let (back2, exit_wi) = {
            let builder = TcExitWanIngressSkelBuilder::default();
            let (back, obj) = OwnedOpenObject::new();
            let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_exit_wan_ingress skeleton")?;
            crate::map_setting::reuse_pinned_map_or_recreate(
                &mut open_skel.maps.tc_pipe_exits_wan_ingress,
                &tc_pipe_exits_wan_ingress_path(),
            );
            let skel = bpf_ctx!(open_skel.load(), "load tc_exit_wan_ingress skeleton")?;
            let exit_fd = skel.progs.tc_exit_wan_ingress_redirect.as_fd().as_raw_fd();
            skel.maps.tc_pipe_exits_wan_ingress.update(
                &0u32.to_ne_bytes(),
                &exit_fd.to_ne_bytes(),
                MapFlags::ANY,
            )?;
            (back, skel)
        };

        // 3. tc_exit_wan_egress — tc_pipe_exits_wan_egress
        let (back3, exit_we) = {
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
            (back, skel)
        };

        // 4. tc_exit_lan_ingress — tc_pipe_exits_lan_ingress
        let (back4, exit_li) = {
            let builder = TcExitLanIngressSkelBuilder::default();
            let (back, obj) = OwnedOpenObject::new();
            let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_exit_lan_ingress skeleton")?;
            crate::map_setting::reuse_pinned_map_or_recreate(
                &mut open_skel.maps.tc_pipe_exits_lan_ingress,
                &tc_pipe_exits_lan_ingress_path(),
            );
            let skel = bpf_ctx!(open_skel.load(), "load tc_exit_lan_ingress skeleton")?;
            let exit_fd = skel.progs.tc_exit_lan_ingress_redirect.as_fd().as_raw_fd();
            skel.maps.tc_pipe_exits_lan_ingress.update(
                &0u32.to_ne_bytes(),
                &exit_fd.to_ne_bytes(),
                MapFlags::ANY,
            )?;
            (back, skel)
        };

        // 5. tc_lan_ingress_chain — tc_lan_ingress_roots
        let (back5, lan_ingress_chain): (
            OwnedOpenObject,
            tc_lan_ingress_chain_skel::TcLanIngressChainSkel<'static>,
        ) = {
            let builder = TcLanIngressChainSkelBuilder::default();
            let (back, obj) = OwnedOpenObject::new();
            let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_lan_ingress_chain skeleton")?;
            crate::map_setting::reuse_pinned_map_or_recreate(
                &mut open_skel.maps.tc_lan_ingress_roots,
                &tc_lan_ingress_roots_path(),
            );
            crate::map_setting::reuse_pinned_map_or_recreate(
                &mut open_skel.maps.tc_pipe_exits_lan_ingress,
                &tc_pipe_exits_lan_ingress_path(),
            );
            let skel = bpf_ctx!(open_skel.load(), "load tc_lan_ingress_chain skeleton")?;
            (back, skel)
        };

        // 6. tc_wan_egress_chain — tc_wan_egress_roots
        let (back6, wan_egress_chain): (
            OwnedOpenObject,
            tc_wan_egress_chain_skel::TcWanEgressChainSkel<'static>,
        ) = {
            let builder = TcWanEgressChainSkelBuilder::default();
            let (back, obj) = OwnedOpenObject::new();
            let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_wan_egress_chain skeleton")?;
            crate::map_setting::reuse_pinned_map_or_recreate(
                &mut open_skel.maps.tc_wan_egress_roots,
                &tc_wan_egress_roots_path(),
            );
            let skel = bpf_ctx!(open_skel.load(), "load tc_wan_egress_chain skeleton")?;
            (back, skel)
        };

        Ok(Self {
            _seed: seed,
            _exit_wi: exit_wi,
            _exit_we: exit_we,
            _exit_li: exit_li,
            _lan_ingress_chain: lan_ingress_chain,
            _wan_egress_chain: wan_egress_chain,
            _back1: back1,
            _back2: back2,
            _back3: back3,
            _back4: back4,
            _back5: back5,
            _back6: back6,
            inner: Mutex::new(ManagerInner::new()),
        })
    }

    pub fn ensure_roots(&self, ifindex: u32) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_roots_locked(&mut inner, ifindex)
    }

    fn ensure_roots_locked(&self, inner: &mut ManagerInner, ifindex: u32) -> LdEbpfResult<()> {
        let state = inner.interfaces.entry(ifindex).or_default();
        if state.roots.is_some() {
            return Ok(());
        }
        state.roots = Some(self.create_roots(ifindex)?);
        Ok(())
    }

    fn create_roots(&self, ifindex: u32) -> LdEbpfResult<TcRoots> {
        let (
            wan_chain_skel,
            wan_chain_backing,
            wan_ingress_root_next_stage_fd,
            wan_egress_root_next_stage_fd,
        ) = {
            let builder = TcWanChainSkelBuilder::default();
            let (back, obj) = OwnedOpenObject::new();
            let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_wan_chain")?;

            open_skel.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = ifindex;

            pin_and_reuse_map(
                &mut open_skel.maps.tc_pipe_exits_wan_ingress,
                &tc_pipe_exits_wan_ingress_path(),
            )?;
            pin_and_reuse_map(
                &mut open_skel.maps.tc_pipe_exits_wan_egress,
                &tc_pipe_exits_wan_egress_path(),
            )?;

            let skel = bpf_ctx!(open_skel.load(), "load tc_wan_chain")?;

            let ingress_root_fd = skel.progs.tc_wan_chain_ingress_root.as_fd().as_raw_fd();
            let egress_root_fd = skel.progs.tc_wan_chain_egress_root.as_fd().as_raw_fd();
            let ing_next_fd = skel.maps.wan_ingress_root_next_stage.as_fd().as_raw_fd();
            let eg_next_fd = skel.maps.wan_egress_root_next_stage.as_fd().as_raw_fd();

            self._seed.maps.tc_pipe_root_progs.update(
                &ifindex.to_ne_bytes(),
                &ingress_root_fd.to_ne_bytes(),
                MapFlags::ANY,
            )?;

            let mut dispatch_key = [0u8; 16];
            dispatch_key[0..4].copy_from_slice(&TC_INTRO_IFINDEX_TYPE.to_le_bytes());
            dispatch_key[8..12].copy_from_slice(&ifindex.to_le_bytes());
            let dispatch_val = ifindex.to_ne_bytes();
            self._seed.maps.wan_intro_dispatch_map.update(
                &dispatch_key,
                &dispatch_val,
                MapFlags::ANY,
            )?;

            self._wan_egress_chain.maps.tc_wan_egress_roots.update(
                &ifindex.to_ne_bytes(),
                &egress_root_fd.to_ne_bytes(),
                MapFlags::ANY,
            )?;

            (skel, back, ing_next_fd, eg_next_fd)
        };

        let (lan_chain_skel, lan_chain_backing, lan_ingress_root_next_stage_fd) = {
            let builder = TcLanChainSkelBuilder::default();
            let (back, obj) = OwnedOpenObject::new();
            let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_lan_chain")?;

            open_skel.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = ifindex;

            pin_and_reuse_map(
                &mut open_skel.maps.tc_lan_ingress_roots,
                &tc_lan_ingress_roots_path(),
            )?;
            pin_and_reuse_map(
                &mut open_skel.maps.tc_pipe_exits_lan_ingress,
                &tc_pipe_exits_lan_ingress_path(),
            )?;

            let skel = bpf_ctx!(open_skel.load(), "load tc_lan_chain")?;

            let lan_root_fd = skel.progs.tc_lan_chain_ingress_root.as_fd().as_raw_fd();
            let lan_next_fd = skel.maps.lan_ingress_root_next_stage.as_fd().as_raw_fd();

            self._lan_ingress_chain.maps.tc_lan_ingress_roots.update(
                &ifindex.to_ne_bytes(),
                &lan_root_fd.to_ne_bytes(),
                MapFlags::ANY,
            )?;

            (skel, back, lan_next_fd)
        };

        Ok(TcRoots {
            _wan_chain_skel: wan_chain_skel,
            _wan_chain_backing: wan_chain_backing,
            wan_ingress_root_next_stage_fd,
            wan_egress_root_next_stage_fd,
            _lan_chain_skel: lan_chain_skel,
            _lan_chain_backing: lan_chain_backing,
            lan_ingress_root_next_stage_fd,
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
        self.rebuild(ifindex, ChainDir::LanIngress)?;
        Ok(())
    }

    pub fn remove_roots(&self, ifindex: u32) {
        let mut inner = self.inner.lock().unwrap();
        if inner.interfaces.remove(&ifindex).is_none() {
            return;
        }

        // Clean up dispatch / prog-array registrations created in create_roots
        let _ = self._seed.maps.tc_pipe_root_progs.delete(&ifindex.to_ne_bytes());
        let _ = self._wan_egress_chain.maps.tc_wan_egress_roots.delete(&ifindex.to_ne_bytes());
        let _ = self._lan_ingress_chain.maps.tc_lan_ingress_roots.delete(&ifindex.to_ne_bytes());

        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&TC_INTRO_IFINDEX_TYPE.to_le_bytes());
        dispatch_key[8..12].copy_from_slice(&ifindex.to_le_bytes());
        let _ = self._seed.maps.wan_intro_dispatch_map.delete(&dispatch_key);
    }

    pub fn remove(&self, ifindex: u32, stage: StageType) -> LdEbpfResult<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(state) = inner.interfaces.get_mut(&ifindex) {
                state.stages.remove(&stage);
            }
        }
        self.rebuild(ifindex, ChainDir::WanIngress)?;
        self.rebuild(ifindex, ChainDir::WanEgress)?;
        self.rebuild(ifindex, ChainDir::LanIngress)?;
        Ok(())
    }

    fn rebuild(&self, ifindex: u32, chain: ChainDir) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_roots_locked(&mut inner, ifindex)?;

        let state = inner.interfaces.get_mut(&ifindex).unwrap();
        let roots = state.roots.as_ref().unwrap();

        let root_next_stage_fd = match chain {
            ChainDir::WanIngress => roots.wan_ingress_root_next_stage_fd,
            ChainDir::WanEgress => roots.wan_egress_root_next_stage_fd,
            ChainDir::LanIngress => roots.lan_ingress_root_next_stage_fd,
        };

        for (_, entry) in &state.stages {
            let next_fd = match chain {
                ChainDir::WanIngress => entry.wan_ingress_next_stage_fd,
                ChainDir::WanEgress => entry.wan_egress_next_stage_fd,
                ChainDir::LanIngress => entry.lan_ingress_next_stage_fd,
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
            .collect();
        if sorted.is_empty() {
            return Ok(());
        }

        let first_prog_fd = match chain {
            ChainDir::WanIngress => sorted[0].wan_ingress_prog_fd,
            ChainDir::WanEgress => sorted[0].wan_egress_prog_fd,
            ChainDir::LanIngress => sorted[0].lan_ingress_prog_fd,
        };
        update_prog_array_fd(root_next_stage_fd, 0, first_prog_fd)?;

        for i in 0..sorted.len().saturating_sub(1) {
            let next_fd = match chain {
                ChainDir::WanIngress => sorted[i].wan_ingress_next_stage_fd,
                ChainDir::WanEgress => sorted[i].wan_egress_next_stage_fd,
                ChainDir::LanIngress => sorted[i].lan_ingress_next_stage_fd,
            };
            let next_prog_fd = match chain {
                ChainDir::WanIngress => sorted[i + 1].wan_ingress_prog_fd,
                ChainDir::WanEgress => sorted[i + 1].wan_egress_prog_fd,
                ChainDir::LanIngress => sorted[i + 1].lan_ingress_prog_fd,
            };
            update_prog_array_fd(next_fd, 0, next_prog_fd)?;
        }

        Ok(())
    }
}
