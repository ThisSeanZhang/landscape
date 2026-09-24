//! Per-link stage-chain state.
//!
//! One [`LinkChain`] owns the stage-chain roots of a single WAN link's
//! attach interface: the XDP Lan/Wan direction roots, the TC
//! WanIngress/WanEgress roots, and the stage table linking them together.
//! The Lan-direction chain is the symmetric (LAN-ingress) pipeline of the
//! same WAN link — both are keyed by ifindex for now and will move to
//! `link_chain_id` with the chain-id refactor.
//!
//! Lifecycle is driven by the link service: [`ChainHub::open_link_chain`]
//! creates the roots and registers them in the shared prog-array /
//! dispatch maps when the link goes up, and the drop of the link's chain
//! guard removes them when the link ends. Stage attach/detach
//! (`inject_*` / `remove_*`) is driven by the per-link sections
//! (nat / firewall / mss / pppoe) through the [`LinkChain`] handle they
//! capture at attach time.

use std::collections::BTreeMap;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Arc, Mutex};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::chain::hub::ChainHub;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};

pub(crate) mod xdp_wan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_chain.skel.rs"));
}
pub(crate) mod xdp_lan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_chain.skel.rs"));
}
mod tc_wan_ingress_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_root.skel.rs"));
}
mod tc_wan_egress_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_root.skel.rs"));
}

use tc_wan_egress_root_skel::TcWanEgressRootSkelBuilder;
use tc_wan_ingress_root_skel::TcWanIngressRootSkelBuilder;
use xdp_lan_chain_skel::XdpLanChainSkelBuilder;
use xdp_wan_chain_skel::XdpWanChainSkelBuilder;

const TC_INTRO_IFINDEX_TYPE: u32 = 2;
const WAN_INTRO_IFINDEX_TYPE: u32 = 2;

/// Chain stage kinds, shared by the XDP and TC stage tables.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StageType {
    Mss = 0,
    Firewall = 1,
    Nat = 2,
    Pppoe = 3,
}

/// XDP chain direction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainDir {
    Lan,
    Wan,
}

impl std::fmt::Debug for ChainDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainDir::Lan => write!(f, "Lan"),
            ChainDir::Wan => write!(f, "Wan"),
        }
    }
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

fn pinned_map(path: &std::path::Path) -> LdEbpfResult<MapHandle> {
    MapHandle::from_pinned_path(path).map_err(|e| crate::bpf_error::LandscapeEbpfError::Context {
        context: format!("open pinned map {}", path.display()),
        source: e,
    })
}

// ─────────────────────────────────────────────────────────────────────────
// Root skeletons
// ─────────────────────────────────────────────────────────────────────────

enum XdpChainRoot {
    Wan {
        _skel: xdp_wan_chain_skel::XdpWanChainSkel<'static>,
        _backing: OwnedOpenObject,
        root_next_stage_fd: i32,
    },
    Lan {
        _skel: xdp_lan_chain_skel::XdpLanChainSkel<'static>,
        _backing: OwnedOpenObject,
        root_next_stage_fd: i32,
    },
}

impl XdpChainRoot {
    fn root_next_stage_fd(&self) -> i32 {
        match self {
            XdpChainRoot::Wan { root_next_stage_fd, .. } => *root_next_stage_fd,
            XdpChainRoot::Lan { root_next_stage_fd, .. } => *root_next_stage_fd,
        }
    }
}

struct TcIngressRoot {
    _skel: tc_wan_ingress_root_skel::TcWanIngressRootSkel<'static>,
    _backing: OwnedOpenObject,
    next_stage_fd: i32,
}

struct TcEgressRoot {
    _skel: tc_wan_egress_root_skel::TcWanEgressRootSkel<'static>,
    _backing: OwnedOpenObject,
    next_stage_fd: i32,
}

// ─────────────────────────────────────────────────────────────────────────
// Stage entries
// ─────────────────────────────────────────────────────────────────────────

/// XDP stage: one program (per direction) plus its next-stage prog array.
#[derive(Clone, Copy)]
struct XdpStageEntry {
    prog_fd: i32,
    next_stage_map_fd: i32,
}

/// TC stage: ingress + egress program pair with their next-stage prog arrays.
#[derive(Clone, Copy)]
pub struct TcStageEntry {
    pub wan_ingress_prog_fd: i32,
    pub wan_egress_prog_fd: i32,
    pub wan_ingress_next_stage_fd: i32,
    pub wan_egress_next_stage_fd: i32,
}

// ─────────────────────────────────────────────────────────────────────────
// LinkChain
// ─────────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct LinkChainInner {
    closed: bool,
    has_mac: bool,
    /// Link metadata only for now: all root slots are still keyed by
    /// ifindex. TODO(chain-id refactor): key the roots by `link_chain_id`
    /// instead; LAN ifaces (id 0) will not own a chain then.
    link_chain_id: u16,
    xdp_lan_root: Option<XdpChainRoot>,
    xdp_wan_root: Option<XdpChainRoot>,
    tc_ingress_root: Option<TcIngressRoot>,
    tc_egress_root: Option<TcEgressRoot>,
    xdp_lan_stages: BTreeMap<StageType, XdpStageEntry>,
    xdp_wan_stages: BTreeMap<StageType, XdpStageEntry>,
    tc_stages: BTreeMap<StageType, TcStageEntry>,
}

pub struct LinkChain {
    hub: Arc<ChainHub>,
    ifindex: u32,
    inner: Mutex<LinkChainInner>,
}

impl LinkChain {
    /// Create an empty chain state for `ifindex`. Roots are created lazily by
    /// [`LinkChain::open_roots`] or by the first stage injection.
    pub(crate) fn create(hub: Arc<ChainHub>, ifindex: u32) -> LdEbpfResult<Arc<Self>> {
        Ok(Arc::new(Self {
            hub,
            ifindex,
            inner: Mutex::new(LinkChainInner::default()),
        }))
    }

    pub(crate) fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Create (once) and register the XDP and TC chain roots for this
    /// interface, and record the link metadata.
    pub fn open_roots(&self, has_mac: bool, link_chain_id: u16) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("open closed link chain ifindex={}", self.ifindex),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENOENT),
            });
        }
        inner.has_mac = has_mac;
        inner.link_chain_id = link_chain_id;
        if inner.xdp_wan_root.is_none() {
            inner.xdp_wan_root = Some(self.create_wan_root()?);
        }
        if inner.xdp_lan_root.is_none() {
            inner.xdp_lan_root = Some(self.create_lan_root()?);
        }
        if inner.tc_ingress_root.is_none() {
            let l3_offset: u32 = if has_mac { 14 } else { 0 };
            inner.tc_ingress_root = Some(self.create_ingress_root(l3_offset)?);
        }
        if inner.tc_egress_root.is_none() {
            inner.tc_egress_root = Some(self.create_egress_root()?);
        }
        Ok(())
    }

    // ── XDP stage table ──────────────────────────────────────────────────

    pub(crate) fn inject_xdp(
        &self,
        stage: StageType,
        lan_prog_fd: i32,
        wan_prog_fd: i32,
        next_stage_map_fd: i32,
    ) -> LdEbpfResult<()> {
        let (old_lan, old_wan, had_lan_root, had_wan_root) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                return Err(crate::bpf_error::LandscapeEbpfError::Context {
                    context: format!("inject into closed link chain ifindex={}", self.ifindex),
                    source: libbpf_rs::Error::from_raw_os_error(libc::ENOENT),
                });
            }
            (
                inner
                    .xdp_lan_stages
                    .insert(stage, XdpStageEntry { prog_fd: lan_prog_fd, next_stage_map_fd }),
                inner
                    .xdp_wan_stages
                    .insert(stage, XdpStageEntry { prog_fd: wan_prog_fd, next_stage_map_fd }),
                inner.xdp_lan_root.is_some(),
                inner.xdp_wan_root.is_some(),
            )
        };
        if let Err(err) =
            self.rebuild_xdp(ChainDir::Lan).and_then(|_| self.rebuild_xdp(ChainDir::Wan))
        {
            let mut inner = self.inner.lock().unwrap();
            if !inner.closed {
                match old_lan {
                    Some(entry) => {
                        inner.xdp_lan_stages.insert(stage, entry);
                    }
                    None => {
                        inner.xdp_lan_stages.remove(&stage);
                    }
                }
                match old_wan {
                    Some(entry) => {
                        inner.xdp_wan_stages.insert(stage, entry);
                    }
                    None => {
                        inner.xdp_wan_stages.remove(&stage);
                    }
                }
            }
            drop(inner);
            let _ = self.rebuild_xdp(ChainDir::Lan);
            let _ = self.rebuild_xdp(ChainDir::Wan);
            if !had_lan_root || !had_wan_root {
                self.remove_xdp_roots();
            }
            return Err(err);
        }
        Ok(())
    }

    pub(crate) fn remove_xdp(&self, stage: StageType) -> LdEbpfResult<()> {
        let (old_lan, old_wan, has_remaining_stages) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                return Ok(());
            }
            let old_lan = inner.xdp_lan_stages.remove(&stage);
            let old_wan = inner.xdp_wan_stages.remove(&stage);
            let has_remaining_stages =
                !inner.xdp_lan_stages.is_empty() || !inner.xdp_wan_stages.is_empty();
            (old_lan, old_wan, has_remaining_stages)
        };
        let result = if has_remaining_stages {
            self.rebuild_xdp(ChainDir::Lan).and_then(|_| self.rebuild_xdp(ChainDir::Wan))
        } else {
            self.remove_xdp_roots();
            Ok(())
        };
        if let Err(err) = result {
            let mut inner = self.inner.lock().unwrap();
            if !inner.closed {
                if let Some(entry) = old_lan {
                    inner.xdp_lan_stages.insert(stage, entry);
                }
                if let Some(entry) = old_wan {
                    inner.xdp_wan_stages.insert(stage, entry);
                }
            }
            drop(inner);
            let _ = self.rebuild_xdp(ChainDir::Lan);
            let _ = self.rebuild_xdp(ChainDir::Wan);
            return Err(err);
        }
        Ok(())
    }

    // ── TC stage table ───────────────────────────────────────────────────

    pub(crate) fn inject_tc(&self, stage: StageType, entry: TcStageEntry) -> LdEbpfResult<()> {
        let (old, had_ingress_root, had_egress_root) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                return Err(crate::bpf_error::LandscapeEbpfError::Context {
                    context: format!("inject into closed link chain ifindex={}", self.ifindex),
                    source: libbpf_rs::Error::from_raw_os_error(libc::ENOENT),
                });
            }
            (
                inner.tc_stages.insert(stage, entry),
                inner.tc_ingress_root.is_some(),
                inner.tc_egress_root.is_some(),
            )
        };
        if let Err(err) = self
            .rebuild_tc(TcChainDir::WanIngress)
            .and_then(|_| self.rebuild_tc(TcChainDir::WanEgress))
        {
            let mut inner = self.inner.lock().unwrap();
            if !inner.closed {
                match old {
                    Some(previous) => {
                        inner.tc_stages.insert(stage, previous);
                    }
                    None => {
                        inner.tc_stages.remove(&stage);
                    }
                }
            }
            drop(inner);
            let _ = self.rebuild_tc(TcChainDir::WanIngress);
            let _ = self.rebuild_tc(TcChainDir::WanEgress);
            if !had_ingress_root || !had_egress_root {
                self.remove_tc_roots();
            }
            return Err(err);
        }
        Ok(())
    }

    pub(crate) fn remove_tc(&self, stage: StageType) -> LdEbpfResult<()> {
        let (old, empty) = {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                return Ok(());
            }
            let old = inner.tc_stages.remove(&stage);
            (old, inner.tc_stages.is_empty())
        };
        let result = if empty {
            self.remove_tc_roots();
            Ok(())
        } else {
            self.rebuild_tc(TcChainDir::WanIngress)
                .and_then(|_| self.rebuild_tc(TcChainDir::WanEgress))
        };
        if let Err(err) = result {
            let mut inner = self.inner.lock().unwrap();
            if !inner.closed {
                if let Some(previous) = old {
                    inner.tc_stages.insert(stage, previous);
                }
            }
            drop(inner);
            let _ = self.rebuild_tc(TcChainDir::WanIngress);
            let _ = self.rebuild_tc(TcChainDir::WanEgress);
            return Err(err);
        }
        Ok(())
    }

    // ── Teardown ─────────────────────────────────────────────────────────

    /// Tear down the XDP chain roots so their programs can unload.
    ///
    /// A root is only removed once no XDP stages remain registered for it:
    /// while stages are still attached their bookkeeping must survive so the
    /// chain can be relinked when the route service restarts.
    pub(crate) fn remove_xdp_roots(&self) {
        let (lan_cleanup, wan_cleanup) = {
            let mut inner = self.inner.lock().unwrap();
            let lan_cleanup = inner.xdp_lan_stages.is_empty();
            let wan_cleanup = inner.xdp_wan_stages.is_empty();
            if lan_cleanup {
                inner.xdp_lan_root.take();
            }
            if wan_cleanup {
                inner.xdp_wan_root.take();
            }
            (lan_cleanup, wan_cleanup)
        };

        if wan_cleanup {
            let seed = self.hub.xdp_seed();
            let _ = seed.maps.xdp_pipe_root_progs.delete(&self.ifindex.to_ne_bytes());
            let mut dispatch_key = [0u8; 16];
            dispatch_key[0..4].copy_from_slice(&WAN_INTRO_IFINDEX_TYPE.to_le_bytes());
            dispatch_key[8..12].copy_from_slice(&self.ifindex.to_le_bytes());
            let _ = seed.maps.wan_intro_dispatch_map.delete(&dispatch_key);
        }
        if lan_cleanup {
            let seed = self.hub.xdp_seed();
            let _ = seed.maps.xdp_lan_pipe_root_progs.delete(&self.ifindex.to_ne_bytes());
        }
    }

    /// Permanently close this chain generation and discard all stage state.
    /// Global XDP exit slots are intentionally left installed in the hub.
    pub(crate) fn close(&self) {
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.closed {
                return;
            }
            inner.closed = true;
            inner.xdp_lan_stages.clear();
            inner.xdp_wan_stages.clear();
            inner.tc_stages.clear();
        }
        self.remove_xdp_roots();
        self.remove_tc_roots();
    }

    /// Tear down the TC chain roots and their map registrations.
    pub(crate) fn remove_tc_roots(&self) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.tc_ingress_root = None;
            inner.tc_egress_root = None;
        }

        if let Ok(map) = pinned_map(&self.hub.paths.tc_pipe_root_progs_path()) {
            let _ = map.delete(&self.ifindex.to_ne_bytes());
        }
        if let Ok(map) = pinned_map(&self.hub.paths.tc_wan_egress_roots_path()) {
            let _ = map.delete(&self.ifindex.to_ne_bytes());
        }

        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&TC_INTRO_IFINDEX_TYPE.to_le_bytes());
        dispatch_key[8..12].copy_from_slice(&self.ifindex.to_le_bytes());
        if let Ok(map) = pinned_map(&self.hub.paths.tc_wan_intro_dispatch_path()) {
            let _ = map.delete(&dispatch_key);
        }
    }

    // ── Root creation ────────────────────────────────────────────────────

    fn create_wan_root(&self) -> LdEbpfResult<XdpChainRoot> {
        let paths = &self.hub.paths;
        let builder = XdpWanChainSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_chain")?;

        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &paths.xdp_pipe_exits_lan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &paths.xdp_pipe_exits_wan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        )?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_wan_chain")?;

        let root_prog_fd = skel.progs.xdp_wan_chain_root.as_fd().as_raw_fd();
        let root_next_fd = skel.maps.root_next_stage.as_fd().as_raw_fd();

        let slot_bytes = self.ifindex.to_ne_bytes();
        let root_bytes = root_prog_fd.to_ne_bytes();
        self.hub.xdp_seed().maps.xdp_pipe_root_progs.update(
            &slot_bytes,
            &root_bytes,
            MapFlags::ANY,
        )?;

        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&WAN_INTRO_IFINDEX_TYPE.to_le_bytes());
        dispatch_key[8..12].copy_from_slice(&self.ifindex.to_le_bytes());
        let dispatch_val = self.ifindex.to_ne_bytes();
        self.hub.xdp_seed().maps.wan_intro_dispatch_map.update(
            &dispatch_key,
            &dispatch_val,
            MapFlags::ANY,
        )?;

        Ok(XdpChainRoot::Wan {
            _skel: skel,
            _backing: backing,
            root_next_stage_fd: root_next_fd,
        })
    }

    fn create_lan_root(&self) -> LdEbpfResult<XdpChainRoot> {
        let paths = &self.hub.paths;
        let builder = XdpLanChainSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_chain")?;

        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &paths.xdp_pipe_exits_lan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &paths.xdp_pipe_exits_wan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able)?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_chain")?;

        let root_prog_fd = skel.progs.xdp_lan_chain_root.as_fd().as_raw_fd();
        let root_next_fd = skel.maps.root_next_stage.as_fd().as_raw_fd();

        self.hub.xdp_seed().maps.xdp_lan_pipe_root_progs.update(
            &self.ifindex.to_ne_bytes(),
            &root_prog_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(XdpChainRoot::Lan {
            _skel: skel,
            _backing: backing,
            root_next_stage_fd: root_next_fd,
        })
    }

    fn create_ingress_root(&self, l3_offset: u32) -> LdEbpfResult<TcIngressRoot> {
        let paths = &self.hub.paths;
        let ingress_builder = TcWanIngressRootSkelBuilder::default();
        let (ingress_back, ingress_obj) = OwnedOpenObject::new();
        let mut ingress_open_skel =
            bpf_ctx!(ingress_builder.open(ingress_obj), "open tc_wan_ingress_root")?;

        ingress_open_skel.maps.rodata_data.as_deref_mut().unwrap().current_l3_offset = l3_offset;

        pin_and_reuse_map(
            &mut ingress_open_skel.maps.tc_pipe_exits_wan_ingress,
            &paths.tc_pipe_exits_wan_ingress_path(),
        )?;

        let ingress_skel = bpf_ctx!(ingress_open_skel.load(), "load tc_wan_ingress_root")?;

        let ingress_root_fd = ingress_skel.progs.tc_wan_chain_ingress_root.as_fd().as_raw_fd();
        let ing_next_fd = ingress_skel.maps.wan_ingress_root_next_stage.as_fd().as_raw_fd();

        pinned_map(&paths.tc_pipe_root_progs_path())?.update(
            &self.ifindex.to_ne_bytes(),
            &ingress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&TC_INTRO_IFINDEX_TYPE.to_le_bytes());
        dispatch_key[8..12].copy_from_slice(&self.ifindex.to_le_bytes());
        let dispatch_val = self.ifindex.to_ne_bytes();
        pinned_map(&paths.tc_wan_intro_dispatch_path())?.update(
            &dispatch_key,
            &dispatch_val,
            MapFlags::ANY,
        )?;

        Ok(TcIngressRoot {
            _skel: ingress_skel,
            _backing: ingress_back,
            next_stage_fd: ing_next_fd,
        })
    }

    fn create_egress_root(&self) -> LdEbpfResult<TcEgressRoot> {
        let paths = &self.hub.paths;
        let egress_builder = TcWanEgressRootSkelBuilder::default();
        let (egress_back, egress_obj) = OwnedOpenObject::new();
        let mut egress_open_skel =
            bpf_ctx!(egress_builder.open(egress_obj), "open tc_wan_egress_root")?;

        pin_and_reuse_map(
            &mut egress_open_skel.maps.tc_pipe_exits_wan_egress,
            &paths.tc_pipe_exits_wan_egress_path(),
        )?;

        let egress_skel = bpf_ctx!(egress_open_skel.load(), "load tc_wan_egress_root")?;

        let egress_root_fd = egress_skel.progs.tc_wan_chain_egress_root.as_fd().as_raw_fd();
        let eg_next_fd = egress_skel.maps.wan_egress_root_next_stage.as_fd().as_raw_fd();

        pinned_map(&paths.tc_wan_egress_roots_path())?.update(
            &self.ifindex.to_ne_bytes(),
            &egress_root_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(TcEgressRoot {
            _skel: egress_skel,
            _backing: egress_back,
            next_stage_fd: eg_next_fd,
        })
    }

    // ── Rebuild ──────────────────────────────────────────────────────────

    fn ensure_xdp_roots_locked(&self, inner: &mut LinkChainInner) -> LdEbpfResult<()> {
        if inner.xdp_wan_root.is_none() {
            inner.xdp_wan_root = Some(self.create_wan_root()?);
        }
        if inner.xdp_lan_root.is_none() {
            inner.xdp_lan_root = Some(self.create_lan_root()?);
        }
        Ok(())
    }

    fn rebuild_xdp(&self, chain: ChainDir) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("rebuild closed link chain ifindex={}", self.ifindex),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENOENT),
            });
        }
        self.ensure_xdp_roots_locked(&mut inner)?;

        let dir_slot = match chain {
            ChainDir::Lan => 0u32,
            ChainDir::Wan => 1u32,
        };
        let stages = match chain {
            ChainDir::Lan => &inner.xdp_lan_stages,
            ChainDir::Wan => &inner.xdp_wan_stages,
        };

        for entry in stages.values() {
            delete_prog_array_fd(entry.next_stage_map_fd, dir_slot);
        }
        let root = match chain {
            ChainDir::Lan => inner.xdp_lan_root.as_ref().unwrap(),
            ChainDir::Wan => inner.xdp_wan_root.as_ref().unwrap(),
        };
        delete_prog_array_fd(root.root_next_stage_fd(), 0);

        let sorted: Vec<&XdpStageEntry> = stages
            .iter()
            .filter(|(k, _)| !matches!((*k, chain), (StageType::Pppoe, ChainDir::Wan)))
            .map(|(_, v)| v)
            .collect();
        if sorted.is_empty() {
            return Ok(());
        }

        update_prog_array_fd(root.root_next_stage_fd(), 0, sorted[0].prog_fd)?;

        for i in 0..sorted.len().saturating_sub(1) {
            update_prog_array_fd(sorted[i].next_stage_map_fd, dir_slot, sorted[i + 1].prog_fd)?;
        }

        Ok(())
    }

    fn ensure_tc_roots_locked(&self, inner: &mut LinkChainInner) -> LdEbpfResult<()> {
        if inner.tc_ingress_root.is_none() {
            let l3_offset: u32 = if inner.has_mac { 14 } else { 0 };
            inner.tc_ingress_root = Some(self.create_ingress_root(l3_offset)?);
        }
        if inner.tc_egress_root.is_none() {
            inner.tc_egress_root = Some(self.create_egress_root()?);
        }
        Ok(())
    }

    fn rebuild_tc(&self, chain: TcChainDir) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.closed {
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("rebuild closed link chain ifindex={}", self.ifindex),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENOENT),
            });
        }
        self.ensure_tc_roots_locked(&mut inner)?;

        let root_next_stage_fd = match chain {
            TcChainDir::WanIngress => inner.tc_ingress_root.as_ref().unwrap().next_stage_fd,
            TcChainDir::WanEgress => inner.tc_egress_root.as_ref().unwrap().next_stage_fd,
        };

        for entry in inner.tc_stages.values() {
            let next_fd = match chain {
                TcChainDir::WanIngress => entry.wan_ingress_next_stage_fd,
                TcChainDir::WanEgress => entry.wan_egress_next_stage_fd,
            };
            if next_fd != 0 {
                delete_prog_array_fd(next_fd, 0);
            }
        }
        delete_prog_array_fd(root_next_stage_fd, 0);

        let sorted: Vec<&TcStageEntry> = inner
            .tc_stages
            .iter()
            .filter(|(k, _)| !matches!((k, chain), (StageType::Pppoe, TcChainDir::WanIngress)))
            .map(|(_, v)| v)
            .filter(|v| match chain {
                TcChainDir::WanIngress => v.wan_ingress_prog_fd != 0,
                TcChainDir::WanEgress => v.wan_egress_prog_fd != 0,
            })
            .collect();
        if sorted.is_empty() {
            return Ok(());
        }

        let first_prog_fd = match chain {
            TcChainDir::WanIngress => sorted[0].wan_ingress_prog_fd,
            TcChainDir::WanEgress => sorted[0].wan_egress_prog_fd,
        };
        update_prog_array_fd(root_next_stage_fd, 0, first_prog_fd)?;

        for i in 0..sorted.len().saturating_sub(1) {
            let next_fd = match chain {
                TcChainDir::WanIngress => sorted[i].wan_ingress_next_stage_fd,
                TcChainDir::WanEgress => sorted[i].wan_egress_next_stage_fd,
            };
            let next_prog_fd = match chain {
                TcChainDir::WanIngress => sorted[i + 1].wan_ingress_prog_fd,
                TcChainDir::WanEgress => sorted[i + 1].wan_egress_prog_fd,
            };
            update_prog_array_fd(next_fd, 0, next_prog_fd)?;
        }

        Ok(())
    }
}

/// TC chain direction.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TcChainDir {
    WanIngress,
    WanEgress,
}
