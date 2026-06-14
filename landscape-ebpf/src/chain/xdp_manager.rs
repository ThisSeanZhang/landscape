use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, Program, Xdp, XdpFlags};

use crate::bpf_ctx;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::MAP_PATHS;

pub(crate) mod xdp_wan_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_intro.skel.rs"));
}
pub(crate) mod xdp_wan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_chain.skel.rs"));
}
pub(crate) mod xdp_lan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_chain.skel.rs"));
}

use crate::bpf_rs_shared::xdp_skb_pppoe_skel;

use xdp_lan_chain_skel::XdpLanChainSkelBuilder;
use xdp_wan_chain_skel::XdpWanChainSkelBuilder;
use xdp_wan_intro_skel::XdpWanIntroSkelBuilder;

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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StageType {
    Mss = 0,
    Firewall = 1,
    Nat = 2,
}

pub(crate) fn xdp_pipe_root_progs_path() -> PathBuf {
    MAP_PATHS.xdp_base.join("pipe_root_progs")
}

pub(crate) fn xdp_pipe_exits_lan_path() -> PathBuf {
    MAP_PATHS.xdp_base.join("pipe_exits_lan")
}

pub(crate) fn xdp_pipe_exits_wan_path() -> PathBuf {
    MAP_PATHS.xdp_base.join("pipe_exits_wan")
}

pub(crate) fn xdp_lan_pipe_root_progs_path() -> PathBuf {
    MAP_PATHS.xdp_base.join("lan_pipe_root_progs")
}

pub(crate) fn wan_intro_dispatch_path() -> PathBuf {
    MAP_PATHS.xdp_base.join("wan_intro_dispatch")
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

struct ManagerInner {
    chains: HashMap<(u32, ChainDir), ChainState>,
}

impl ManagerInner {
    fn new() -> Self {
        Self { chains: HashMap::new() }
    }
}

struct ChainState {
    root: Option<ChainRoot>,
    stages: BTreeMap<StageType, StageEntry>,
}

struct StageEntry {
    prog_fd: i32,
    next_stage_map_fd: i32,
}

enum ChainRoot {
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

impl ChainRoot {
    fn root_next_stage_fd(&self) -> i32 {
        match self {
            ChainRoot::Wan { root_next_stage_fd, .. } => *root_next_stage_fd,
            ChainRoot::Lan { root_next_stage_fd, .. } => *root_next_stage_fd,
        }
    }
}

static MANAGER: OnceLock<XdpChainManager> = OnceLock::new();

pub struct XdpChainManager {
    _seed: xdp_wan_intro_skel::XdpWanIntroSkel<'static>,
    _backing: OwnedOpenObject,
    inner: Mutex<ManagerInner>,
    skb_bundles: Mutex<HashMap<u32, SkbXdpBundle>>,
}

// Landscape owns route interfaces, so native XDP attach intentionally replaces
// stale programs left by crashes. Drop detaches during normal shutdown; future
// crash-recovery cleanup can still scan and clear interfaces with disabled
// route services.
pub(crate) struct NativeXdpLink {
    ifindex: i32,
    prog_fd: i32,
}

impl NativeXdpLink {
    pub(crate) fn attach(prog: &Program, ifindex: u32) -> LdEbpfResult<Self> {
        let ifindex_i32 = ifindex as i32;

        // Native and generic (SKB) XDP cannot be active at the same time on
        // the same interface (kernel returns -EEXIST).  Always detach any
        // SKB-mode program unconditionally before attempting native attach,
        // regardless of whether we know about the SKB program through our
        // internal bookkeeping.
        let mut skb_detach_opts = libbpf_sys::bpf_xdp_attach_opts::default();
        skb_detach_opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        let _ = unsafe {
            libbpf_sys::bpf_xdp_detach(ifindex_i32, XdpFlags::SKB_MODE.bits(), &skb_detach_opts)
        };

        // Take the bundle from internal bookkeeping if it exists (the SKB
        // program is already detached above, so the link inside the bundle
        // is stale — we reconstruct it below when re-attaching on failure).
        let skb_bundle = XdpChainManager::instance().take_skb_bundle(ifindex);
        let skb_saved = skb_bundle.map(|b| {
            let (backing, skel) = b.yield_link();
            (backing, skel)
        });

        let result = Self::try_native(prog, ifindex_i32);

        match result {
            Ok(link) => {
                drop(skb_saved);
                Ok(link)
            }
            Err(e) => {
                if let Some((backing, skel)) = skb_saved {
                    match SkbXdpBundle::reattach(backing, skel, ifindex) {
                        Ok(bundle) => {
                            XdpChainManager::instance().set_skb_bundle(ifindex, bundle);
                        }
                        Err(attach_err) => {
                            tracing::warn!(
                                "failed to re-attach SKB XDP on ifindex={ifindex}: {attach_err}"
                            );
                        }
                    }
                }
                Err(e)
            }
        }
    }

    fn try_native(prog: &Program, ifindex: i32) -> LdEbpfResult<Self> {
        #[cfg(debug_assertions)]
        if landscape_common::args::LAND_ARGS.force_native_xdp_fail {
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("native XDP attach force-failed for testing (ifindex={ifindex})"),
                source: libbpf_rs::Error::from_raw_os_error(libc::EOPNOTSUPP),
            });
        }

        let xdp = Xdp::new(prog.as_fd());
        let attach_flags = XdpFlags::DRV_MODE;

        crate::bpf_ctx!(xdp.attach(ifindex, attach_flags), "attach native XDP ifindex={ifindex}")?;

        let query = match crate::bpf_ctx!(
            xdp.query(ifindex, XdpFlags::DRV_MODE),
            "query native XDP ifindex={ifindex}"
        ) {
            Ok(query) => query,
            Err(err) => {
                Self::detach(ifindex, prog.as_fd().as_raw_fd());
                return Err(err.into());
            }
        };
        if query.drv_prog_id == 0 {
            Self::detach(ifindex, prog.as_fd().as_raw_fd());
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("native XDP attach missing drv prog id ifindex={ifindex}"),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENODEV),
            });
        }

        Ok(Self { ifindex, prog_fd: prog.as_fd().as_raw_fd() })
    }

    fn detach(ifindex: i32, prog_fd: i32) {
        let mut opts = libbpf_sys::bpf_xdp_attach_opts::default();
        opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        opts.old_prog_fd = prog_fd;

        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex, XdpFlags::DRV_MODE.bits(), &opts) };
        if ret != 0 {
            tracing::debug!("detach native XDP ifindex={ifindex} failed: {}", -ret);
        }
    }
}

/// Generic/SKB-mode XDP link for fallback scenarios (e.g., PPPoE decap when
/// native XDP is unavailable).
pub(crate) struct SkbXdpLink {
    ifindex: i32,
}

impl SkbXdpLink {
    pub(crate) fn attach(prog: &Program, ifindex: u32) -> LdEbpfResult<Self> {
        let ifindex = ifindex as i32;
        let xdp = Xdp::new(prog.as_fd());
        let attach_flags = XdpFlags::SKB_MODE;

        crate::bpf_ctx!(xdp.attach(ifindex, attach_flags), "attach SKB XDP ifindex={ifindex}")?;

        let query = match crate::bpf_ctx!(
            xdp.query(ifindex, XdpFlags::SKB_MODE),
            "query SKB XDP ifindex={ifindex}"
        ) {
            Ok(query) => query,
            Err(err) => {
                Self::detach(ifindex);
                return Err(err.into());
            }
        };
        if query.skb_prog_id == 0 {
            Self::detach(ifindex);
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("SKB XDP attach missing skb prog id ifindex={ifindex}"),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENODEV),
            });
        }

        Ok(Self { ifindex })
    }

    fn detach(ifindex: i32) {
        let mut opts = libbpf_sys::bpf_xdp_attach_opts::default();
        opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        // old_prog_fd=0 (default) → detach whatever is in SKB mode.
        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex, XdpFlags::SKB_MODE.bits(), &opts) };
        if ret != 0 {
            tracing::warn!("detach SKB XDP ifindex={ifindex} failed: {}", -ret);
        }
    }
}

impl Drop for SkbXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex);
    }
}

/// Bundle holding all resources needed to keep an SKB-mode XDP program
/// alive.  Rust drops fields in reverse declaration order, so *link*
/// (declared last) is dropped first — detaching the XDP program via its
/// real prog_fd.  Then the skeleton and finally the backing memory.
pub(crate) struct SkbXdpBundle {
    _backing: OwnedOpenObject,
    _skel: xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>,
    link: SkbXdpLink,
}

impl SkbXdpBundle {
    pub(crate) fn new(
        backing: OwnedOpenObject,
        skel: xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>,
        link: SkbXdpLink,
    ) -> Self {
        Self { _backing: backing, _skel: skel, link }
    }

    /// Temporarily detach the SKB XDP program (drop the link) and return
    /// the backing + skeleton so the program can be re-attached later.
    fn yield_link(self) -> (OwnedOpenObject, xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>) {
        let SkbXdpBundle { _backing, _skel, link } = self;
        drop(link);
        (_backing, _skel)
    }

    /// Re-attach the SKB XDP program from its backing and skeleton.
    fn reattach(
        backing: OwnedOpenObject,
        skel: xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>,
        ifindex: u32,
    ) -> LdEbpfResult<Self> {
        let link = SkbXdpLink::attach(&skel.progs.xdp_skb_pppoe, ifindex)?;
        Ok(Self { _backing: backing, _skel: skel, link })
    }
}

impl Drop for NativeXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex, self.prog_fd);
    }
}

impl XdpChainManager {
    pub fn instance() -> &'static Self {
        MANAGER.get_or_init(|| Self::init().expect("XDP chain manager init failed"))
    }

    fn init() -> LdEbpfResult<Self> {
        std::fs::create_dir_all(&MAP_PATHS.xdp_base).expect("create xdp_base dir failed");

        let builder = XdpWanIntroSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_intro skeleton")?;

        crate::map_setting::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &xdp_pipe_root_progs_path(),
        );
        crate::map_setting::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &xdp_pipe_exits_lan_path(),
        );
        crate::map_setting::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &xdp_pipe_exits_wan_path(),
        );
        crate::map_setting::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        );
        crate::map_setting::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.wan_intro_dispatch_map,
            &wan_intro_dispatch_path(),
        );

        let skel = bpf_ctx!(open_skel.load(), "load xdp seed skeleton")?;

        Ok(Self {
            _seed: skel,
            _backing: backing,
            inner: Mutex::new(ManagerInner::new()),
            skb_bundles: Mutex::new(HashMap::new()),
        })
    }

    pub fn ensure_roots(&self, ifindex: u32) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_roots_locked(&mut inner, ifindex)
    }

    fn ensure_roots_locked(&self, inner: &mut ManagerInner, ifindex: u32) -> LdEbpfResult<()> {
        let wan_state =
            inner.chains.entry((ifindex, ChainDir::Wan)).or_insert_with(ChainState::default);
        if wan_state.root.is_none() {
            wan_state.root = Some(self.create_wan_root(ifindex)?);
        }
        let lan_state =
            inner.chains.entry((ifindex, ChainDir::Lan)).or_insert_with(ChainState::default);
        if lan_state.root.is_none() {
            lan_state.root = Some(self.create_lan_root(ifindex)?);
        }
        Ok(())
    }

    pub fn inject(
        &self,
        ifindex: u32,
        stage: StageType,
        lan_prog_fd: i32,
        wan_prog_fd: i32,
        next_stage_map_fd: i32,
    ) -> LdEbpfResult<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            let lan_state =
                inner.chains.entry((ifindex, ChainDir::Lan)).or_insert_with(ChainState::default);
            lan_state.stages.insert(stage, StageEntry { prog_fd: lan_prog_fd, next_stage_map_fd });
            let wan_state =
                inner.chains.entry((ifindex, ChainDir::Wan)).or_insert_with(ChainState::default);
            wan_state.stages.insert(stage, StageEntry { prog_fd: wan_prog_fd, next_stage_map_fd });
        }
        self.rebuild(ifindex, ChainDir::Lan)?;
        self.rebuild(ifindex, ChainDir::Wan)?;
        Ok(())
    }

    pub fn remove(&self, ifindex: u32, stage: StageType) -> LdEbpfResult<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(state) = inner.chains.get_mut(&(ifindex, ChainDir::Lan)) {
                state.stages.remove(&stage);
            }
            if let Some(state) = inner.chains.get_mut(&(ifindex, ChainDir::Wan)) {
                state.stages.remove(&stage);
            }
        }
        self.rebuild(ifindex, ChainDir::Lan)?;
        self.rebuild(ifindex, ChainDir::Wan)?;
        Ok(())
    }

    pub fn set_exit(&self, ifindex: u32, exit_fd: i32) -> LdEbpfResult<()> {
        let _ = ifindex;
        let slot = 0u32.to_ne_bytes();
        let val = exit_fd.to_ne_bytes();
        self._seed.maps.xdp_pipe_exits_wan.update(&slot, &val, MapFlags::ANY)?;
        Ok(())
    }

    pub fn clear_exit(&self, ifindex: u32) -> LdEbpfResult<()> {
        let _ = ifindex;
        let slot = 0u32.to_ne_bytes();
        self._seed.maps.xdp_pipe_exits_wan.delete(&slot)?;
        Ok(())
    }

    pub(crate) fn create_wan_intro_link(&self, ifindex: u32) -> LdEbpfResult<NativeXdpLink> {
        let link = NativeXdpLink::attach(&self._seed.progs.wan_intro_dispatch, ifindex)?;
        Ok(link)
    }

    pub(crate) fn set_skb_bundle(&self, ifindex: u32, bundle: SkbXdpBundle) {
        self.skb_bundles.lock().unwrap().insert(ifindex, bundle);
    }

    pub(crate) fn take_skb_bundle(&self, ifindex: u32) -> Option<SkbXdpBundle> {
        self.skb_bundles.lock().unwrap().remove(&ifindex)
    }

    fn create_wan_root(&self, ifindex: u32) -> LdEbpfResult<ChainRoot> {
        let builder = XdpWanChainSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_chain")?;

        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path())?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path())?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path())?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        )?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_wan_chain")?;

        let root_prog_fd = skel.progs.xdp_wan_chain_root.as_fd().as_raw_fd();
        let root_next_fd = skel.maps.root_next_stage.as_fd().as_raw_fd();

        let slot_bytes = ifindex.to_ne_bytes();
        let root_bytes = root_prog_fd.to_ne_bytes();
        self._seed.maps.xdp_pipe_root_progs.update(&slot_bytes, &root_bytes, MapFlags::ANY)?;

        let mut dispatch_key = [0u8; 16];
        dispatch_key[0..4].copy_from_slice(&2u32.to_le_bytes());
        dispatch_key[8..12].copy_from_slice(&ifindex.to_le_bytes());
        let dispatch_val = ifindex.to_ne_bytes();
        self._seed.maps.wan_intro_dispatch_map.update(
            &dispatch_key,
            &dispatch_val,
            MapFlags::ANY,
        )?;

        Ok(ChainRoot::Wan {
            _skel: skel,
            _backing: backing,
            root_next_stage_fd: root_next_fd,
        })
    }

    fn create_lan_root(&self, ifindex: u32) -> LdEbpfResult<ChainRoot> {
        let builder = XdpLanChainSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_chain")?;

        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_root_progs, &xdp_pipe_root_progs_path())?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_lan, &xdp_pipe_exits_lan_path())?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_pipe_exits_wan, &xdp_pipe_exits_wan_path())?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &xdp_lan_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &MAP_PATHS.xdp_redirect_able)?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_chain")?;

        let root_prog_fd = skel.progs.xdp_lan_chain_root.as_fd().as_raw_fd();
        let root_next_fd = skel.maps.root_next_stage.as_fd().as_raw_fd();
        let exit_fd = skel.progs.xdp_lan_chain_exit.as_fd().as_raw_fd();

        self._seed.maps.xdp_lan_pipe_root_progs.update(
            &ifindex.to_ne_bytes(),
            &root_prog_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

        let slot = 0u32.to_ne_bytes();
        let val = exit_fd.to_ne_bytes();
        self._seed.maps.xdp_pipe_exits_lan.update(&slot, &val, MapFlags::ANY)?;

        Ok(ChainRoot::Lan {
            _skel: skel,
            _backing: backing,
            root_next_stage_fd: root_next_fd,
        })
    }

    fn rebuild(&self, ifindex: u32, chain: ChainDir) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_roots_locked(&mut inner, ifindex)?;

        let state = inner.chains.get_mut(&(ifindex, chain)).ok_or_else(|| {
            crate::bpf_error::LandscapeEbpfError::Context {
                context: format!("no chain state for ifindex={} chain={:?}", ifindex, chain),
                source: libbpf_rs::Error::from_raw_os_error(libc::ENOENT),
            }
        })?;

        let root = state.root.as_ref().unwrap();
        let dir_slot = match chain {
            ChainDir::Lan => 0u32,
            ChainDir::Wan => 1u32,
        };

        for (_, entry) in &state.stages {
            delete_prog_array_fd(entry.next_stage_map_fd, dir_slot);
        }
        delete_prog_array_fd(root.root_next_stage_fd(), 0);

        let sorted: Vec<&StageEntry> = state.stages.values().collect();
        if sorted.is_empty() {
            return Ok(());
        }

        update_prog_array_fd(root.root_next_stage_fd(), 0, sorted[0].prog_fd)?;

        for i in 0..sorted.len().saturating_sub(1) {
            update_prog_array_fd(sorted[i].next_stage_map_fd, dir_slot, sorted[i + 1].prog_fd)?;
        }

        Ok(())
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self { root: None, stages: BTreeMap::new() }
    }
}
