use std::collections::{BTreeMap, HashMap};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::sync::{Arc, Mutex};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, Program, Xdp, XdpFlags};

use crate::LandscapeMapPath;
use crate::bpf_ctx;
use crate::bpf_error::{LandscapeEbpfError, LdEbpfResult};
use crate::landscape::{OwnedOpenObject, pin_and_reuse_map};
use crate::runtime::EbpfRuntime;

pub(crate) mod xdp_wan_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_intro.skel.rs"));
}
pub(crate) mod xdp_wan_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_root.skel.rs"));
}
pub(crate) mod xdp_lan_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_root.skel.rs"));
}
pub(crate) mod xdp_lan_exit_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_exit.skel.rs"));
}

use crate::bpf_rs_shared::pppoe_skb_fallback_skel;
use crate::chain::xdp_wan_route::xdp_wan_route_skel;

use xdp_lan_exit_skel::XdpLanExitSkelBuilder;
use xdp_lan_root_skel::XdpLanRootSkelBuilder;
use xdp_wan_intro_skel::XdpWanIntroSkelBuilder;
use xdp_wan_root_skel::XdpWanRootSkelBuilder;
use xdp_wan_route_skel::XdpWanRouteSkelBuilder;

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
    Pppoe = 3,
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

fn clear_map_entries(map: &libbpf_rs::MapMut<'_>) {
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        let _ = map.delete(&key);
    }
}

struct ManagerInner {
    chains: HashMap<(u32, ChainDir), ChainState>,
}

impl ManagerInner {
    fn new() -> Self {
        Self { chains: HashMap::new() }
    }
}

#[derive(Default)]
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
        _skel: xdp_wan_root_skel::XdpWanRootSkel<'static>,
        _backing: OwnedOpenObject,
        root_next_stage_fd: i32,
    },
    Lan {
        _skel: xdp_lan_root_skel::XdpLanRootSkel<'static>,
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

pub struct XdpChainManager {
    paths: Arc<LandscapeMapPath>,
    _seed: xdp_wan_intro_skel::XdpWanIntroSkel<'static>,
    _backing: OwnedOpenObject,
    _exit_lan_skel: xdp_lan_exit_skel::XdpLanExitSkel<'static>,
    _exit_lan_backing: OwnedOpenObject,
    _exit_wan_skel: xdp_wan_route_skel::XdpWanRouteSkel<'static>,
    _exit_wan_backing: OwnedOpenObject,
    inner: Mutex<ManagerInner>,
    skb_bundles: Mutex<HashMap<u32, SkbXdpBundle>>,
    skb_pending: Mutex<HashMap<u32, SkbPending>>,
}

// Landscape owns route interfaces, so native XDP attach intentionally replaces
// stale programs left by crashes. Drop detaches during normal shutdown; future
// crash-recovery cleanup can still scan and clear interfaces with disabled
// route services.
pub(crate) struct NativeXdpLink {
    rt: Arc<EbpfRuntime>,
    ifindex: i32,
    prog_fd: i32,
}

impl NativeXdpLink {
    #[allow(clippy::field_reassign_with_default)]
    pub(crate) fn attach(rt: Arc<EbpfRuntime>, prog: &Program, ifindex: u32) -> LdEbpfResult<Self> {
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

        // Recycle any previously-attached SKB bundle: detach the link
        // (no-op if the unconditional detach above already handled it)
        // and return the skeleton to the pending pool so it can be
        // reused if native XDP fails now or in the future.
        if let Some(old_bundle) = rt.xdp.take_skb_bundle(ifindex) {
            let SkbXdpBundle { _link: _, _skel, _backing } = old_bundle;
            rt.xdp.set_skb_pending(ifindex, SkbPending::new(_backing, _skel));
        }

        let result = Self::try_native(rt.clone(), prog, ifindex_i32);

        match result {
            Ok(link) => {
                // Native XDP succeeded — the pending SKB skeleton remains
                // in the manager untouched.
                Ok(link)
            }
            Err(e) => {
                // Native XDP failed — consume the pending SKB skeleton
                // (if any) and attach it as a fallback.
                if let Some(pending) = rt.xdp.take_skb_pending(ifindex) {
                    let SkbPending { _skel, _backing } = pending;
                    match SkbXdpLink::attach(&_skel.progs.pppoe_skb_fallback, ifindex) {
                        Ok(skb_link) => {
                            let bundle = SkbXdpBundle::new(_backing, _skel, skb_link);
                            rt.xdp.set_skb_bundle(ifindex, bundle);
                        }
                        Err(skb_err) => {
                            tracing::warn!(
                                "native XDP attach failed for ifindex={ifindex}, \
                                 SKB fallback also failed: {skb_err}"
                            );
                        }
                    }
                }
                Err(e)
            }
        }
    }

    fn try_native(rt: Arc<EbpfRuntime>, prog: &Program, ifindex: i32) -> LdEbpfResult<Self> {
        match rt.try_native_xdp.clone() {
            None => {
                return Err(crate::bpf_error::LandscapeEbpfError::Context {
                    context: format!(
                        "native XDP not enabled, use --try-xdp to enable (ifindex={ifindex})"
                    ),
                    source: libbpf_rs::Error::from_raw_os_error(libc::EOPNOTSUPP),
                });
            }
            Some(ref ifindices) => {
                if !ifindices.is_empty() && !ifindices.contains(&ifindex) {
                    return Err(crate::bpf_error::LandscapeEbpfError::Context {
                        context: format!(
                            "native XDP not enabled for this interface (ifindex={ifindex})"
                        ),
                        source: libbpf_rs::Error::from_raw_os_error(libc::EOPNOTSUPP),
                    });
                }
            }
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

        Ok(Self { rt, ifindex, prog_fd: prog.as_fd().as_raw_fd() })
    }

    #[allow(clippy::field_reassign_with_default)]
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

    #[allow(clippy::field_reassign_with_default)]
    fn detach(ifindex: i32) {
        let mut opts = libbpf_sys::bpf_xdp_attach_opts::default();
        opts.sz = size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t;
        // old_prog_fd=0 (default) → detach whatever is in SKB mode.
        let ret = unsafe { libbpf_sys::bpf_xdp_detach(ifindex, XdpFlags::SKB_MODE.bits(), &opts) };
        if ret != 0 {
            tracing::debug!("detach SKB XDP ifindex={ifindex} failed: {}", -ret);
        }
    }
}

impl Drop for SkbXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex);
    }
}

/// An SKB XDP skeleton that has been loaded but NOT yet attached to any
/// interface.  PPPoE prepares one of these and hands it to the manager.
/// The manager decides whether to attach it (as SKB fallback) or keep it
/// for later, depending on native XDP availability.
pub(crate) struct SkbPending {
    _skel: pppoe_skb_fallback_skel::PppoeSkbFallbackSkel<'static>,
    _backing: OwnedOpenObject,
}

impl SkbPending {
    pub(crate) fn new(
        backing: OwnedOpenObject,
        skel: pppoe_skb_fallback_skel::PppoeSkbFallbackSkel<'static>,
    ) -> Self {
        Self { _backing: backing, _skel: skel }
    }
}

/// Bundle holding all resources needed to keep an SKB-mode XDP program
/// alive.  Struct fields are dropped in declaration order, so *link* is
/// dropped first — detaching the XDP program.  Then the skeleton is
/// dropped (OwnedRef accesses the backing which is still alive) and
/// finally the backing memory is freed.
pub(crate) struct SkbXdpBundle {
    _link: SkbXdpLink,
    _skel: pppoe_skb_fallback_skel::PppoeSkbFallbackSkel<'static>,
    _backing: OwnedOpenObject,
}

impl SkbXdpBundle {
    pub(crate) fn new(
        backing: OwnedOpenObject,
        skel: pppoe_skb_fallback_skel::PppoeSkbFallbackSkel<'static>,
        link: SkbXdpLink,
    ) -> Self {
        Self { _backing: backing, _skel: skel, _link: link }
    }
}

impl Drop for NativeXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex, self.prog_fd);
        // If native XDP had failed and SKB was running as fallback,
        // detach it and recycle the skeleton back as pending for reuse.
        if let Some(old_bundle) = self.rt.xdp.take_skb_bundle(self.ifindex as u32) {
            let SkbXdpBundle { _link: _, _skel, _backing } = old_bundle;
            self.rt.xdp.set_skb_pending(self.ifindex as u32, SkbPending::new(_backing, _skel));
        }
    }
}

impl XdpChainManager {
    /// Create the XDP pin directory, seed its prog-array maps, clear stale
    /// entries left by previous runs, and load the per-direction exit programs
    /// (LAN redirect + WAN route) once as manager-lifetime singletons.
    pub fn new(paths: Arc<LandscapeMapPath>) -> LdEbpfResult<Self> {
        std::fs::create_dir_all(&paths.xdp_base).map_err(|e| LandscapeEbpfError::Context {
            context: format!("can not create xdp base dir {}", paths.xdp_base.display()),
            source: e.into(),
        })?;

        let builder = XdpWanIntroSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_intro skeleton")?;

        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &paths.xdp_pipe_root_progs_path(),
        );
        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &paths.xdp_pipe_exits_lan_path(),
        );
        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &paths.xdp_pipe_exits_wan_path(),
        );
        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &paths.xdp_lan_pipe_root_progs_path(),
        );
        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.wan_intro_dispatch_map,
            &paths.xdp_wan_intro_dispatch_path(),
        );

        let skel = bpf_ctx!(open_skel.load(), "load xdp seed skeleton")?;

        // No chains exist in this process yet, so any entry left in these
        // maps belongs to a previous run (crash or kill). Dropping them lets
        // the kernel finally unload the orphaned root/exit programs.
        clear_map_entries(&skel.maps.xdp_pipe_root_progs);
        clear_map_entries(&skel.maps.xdp_lan_pipe_root_progs);
        clear_map_entries(&skel.maps.xdp_pipe_exits_lan);
        clear_map_entries(&skel.maps.xdp_pipe_exits_wan);
        clear_map_entries(&skel.maps.wan_intro_dispatch_map);

        // ── Exit programs are loaded once per manager and stay pinned in the
        // shared exit slots for the manager's whole lifetime. ──

        let (exit_lan_skel, exit_lan_backing) = Self::load_lan_exit()?;
        skel.maps.xdp_pipe_exits_lan.update(
            &0u32.to_ne_bytes(),
            &exit_lan_skel.progs.xdp_lan_exit.as_fd().as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )?;

        let (exit_wan_skel, exit_wan_backing) = Self::load_wan_exit(&paths)?;
        skel.maps.xdp_pipe_exits_wan.update(
            &0u32.to_ne_bytes(),
            &exit_wan_skel.progs.xdp_wan_route_ingress.as_fd().as_raw_fd().to_ne_bytes(),
            MapFlags::ANY,
        )?;

        Ok(Self {
            paths,
            _seed: skel,
            _backing: backing,
            _exit_lan_skel: exit_lan_skel,
            _exit_lan_backing: exit_lan_backing,
            _exit_wan_skel: exit_wan_skel,
            _exit_wan_backing: exit_wan_backing,
            inner: Mutex::new(ManagerInner::new()),
            skb_bundles: Mutex::new(HashMap::new()),
            skb_pending: Mutex::new(HashMap::new()),
        })
    }

    fn load_lan_exit() -> LdEbpfResult<(xdp_lan_exit_skel::XdpLanExitSkel<'static>, OwnedOpenObject)>
    {
        let builder = XdpLanExitSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_exit skeleton")?;
        let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_exit skeleton")?;
        Ok((skel, backing))
    }

    fn load_wan_exit(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(xdp_wan_route_skel::XdpWanRouteSkel<'static>, OwnedOpenObject)> {
        let builder = XdpWanRouteSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_route skeleton")?;

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
        pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map)?;
        pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &paths.wan_ip)?;
        pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &paths.rt4_lan_map)?;
        pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &paths.rt6_lan_map)?;
        pin_and_reuse_map(&mut open_skel.maps.rt4_slot_map, &paths.rt4_slot_map)?;
        pin_and_reuse_map(&mut open_skel.maps.rt6_slot_map, &paths.rt6_slot_map)?;
        pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &paths.flow4_dns_map)?;
        pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &paths.flow6_dns_map)?;
        pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &paths.flow4_ip_map)?;
        pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &paths.flow6_ip_map)?;
        pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &paths.rt4_cache_map)?;
        pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &paths.rt6_cache_map)?;
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &paths.ip_mac_v4)?;
        pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6)?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able)?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_wan_route skeleton")?;
        Ok((skel, backing))
    }

    pub fn ensure_roots(&self, ifindex: u32) -> LdEbpfResult<()> {
        let mut inner = self.inner.lock().unwrap();
        self.ensure_roots_locked(&mut inner, ifindex)
    }

    fn ensure_roots_locked(&self, inner: &mut ManagerInner, ifindex: u32) -> LdEbpfResult<()> {
        let wan_state = inner.chains.entry((ifindex, ChainDir::Wan)).or_default();
        if wan_state.root.is_none() {
            wan_state.root = Some(self.create_wan_root(ifindex)?);
        }
        let lan_state = inner.chains.entry((ifindex, ChainDir::Lan)).or_default();
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
            let lan_state = inner.chains.entry((ifindex, ChainDir::Lan)).or_default();
            lan_state.stages.insert(stage, StageEntry { prog_fd: lan_prog_fd, next_stage_map_fd });
            let wan_state = inner.chains.entry((ifindex, ChainDir::Wan)).or_default();
            wan_state.stages.insert(stage, StageEntry { prog_fd: wan_prog_fd, next_stage_map_fd });
        }
        self.rebuild(ifindex, ChainDir::Lan)?;
        self.rebuild(ifindex, ChainDir::Wan)?;
        Ok(())
    }

    pub fn remove(&self, ifindex: u32, stage: StageType) -> LdEbpfResult<()> {
        let has_remaining_stages;
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(state) = inner.chains.get_mut(&(ifindex, ChainDir::Lan)) {
                state.stages.remove(&stage);
            }
            if let Some(state) = inner.chains.get_mut(&(ifindex, ChainDir::Wan)) {
                state.stages.remove(&stage);
            }
            has_remaining_stages = inner
                .chains
                .get(&(ifindex, ChainDir::Lan))
                .map(|s| !s.stages.is_empty())
                .unwrap_or(false)
                || inner
                    .chains
                    .get(&(ifindex, ChainDir::Wan))
                    .map(|s| !s.stages.is_empty())
                    .unwrap_or(false);
        }
        self.remove_roots(ifindex);
        if has_remaining_stages {
            self.rebuild(ifindex, ChainDir::Lan)?;
            self.rebuild(ifindex, ChainDir::Wan)?;
        }
        Ok(())
    }

    /// Tear down the XDP chains for `ifindex` so their programs can unload.
    ///
    /// A chain is only removed once no stages remain registered for it: while
    /// stages are still attached their bookkeeping must survive so the chain
    /// can be relinked when the route service restarts.
    pub fn remove_roots(&self, ifindex: u32) {
        let mut inner = self.inner.lock().unwrap();

        let lan_removed = Self::remove_chain_locked(&mut inner, ifindex, ChainDir::Lan);
        let wan_removed = Self::remove_chain_locked(&mut inner, ifindex, ChainDir::Wan);

        if wan_removed {
            let _ = self._seed.maps.xdp_pipe_root_progs.delete(&ifindex.to_ne_bytes());
            let mut dispatch_key = [0u8; 16];
            dispatch_key[0..4].copy_from_slice(&2u32.to_le_bytes());
            dispatch_key[8..12].copy_from_slice(&ifindex.to_le_bytes());
            let _ = self._seed.maps.wan_intro_dispatch_map.delete(&dispatch_key);
        }
        if lan_removed {
            let _ = self._seed.maps.xdp_lan_pipe_root_progs.delete(&ifindex.to_ne_bytes());
        }

        // The exit programs are manager-lifetime singletons pinned into the
        // shared exit slots at construction, so they are never cleared here.
    }

    fn remove_chain_locked(inner: &mut ManagerInner, ifindex: u32, chain: ChainDir) -> bool {
        match inner.chains.get(&(ifindex, chain)) {
            Some(state) if !state.stages.is_empty() => return false,
            _ => {}
        }
        inner.chains.remove(&(ifindex, chain)).is_some()
    }

    /// The seed skeleton's wan-intro dispatch program, for callers attaching
    /// a [`NativeXdpLink`] (which needs the owning [`EbpfRuntime`]).
    pub(crate) fn wan_intro_prog(&self) -> &Program<'_> {
        &self._seed.progs.xdp_wan_intro
    }

    pub(crate) fn set_skb_bundle(&self, ifindex: u32, bundle: SkbXdpBundle) {
        self.skb_bundles.lock().unwrap().insert(ifindex, bundle);
    }

    pub(crate) fn take_skb_bundle(&self, ifindex: u32) -> Option<SkbXdpBundle> {
        self.skb_bundles.lock().unwrap().remove(&ifindex)
    }

    pub(crate) fn set_skb_pending(&self, ifindex: u32, pending: SkbPending) {
        let _ = self.skb_bundles.lock().unwrap().remove(&ifindex);

        match crate::maps::redirect_able::get_xdp_redirect_able(&self.paths, ifindex) {
            Some(true) => {
                // Native XDP is already serving this interface — store the
                // skeleton as pending for potential future SKB fallback.
                self.skb_pending.lock().unwrap().insert(ifindex, pending);
            }
            Some(false) => {
                // WR is active but running in TC-only mode — no native XDP
                // on the interface, safe to attach SKB immediately.
                let SkbPending { _skel, _backing } = pending;
                match SkbXdpLink::attach(&_skel.progs.pppoe_skb_fallback, ifindex) {
                    Ok(link) => {
                        let bundle = SkbXdpBundle::new(_backing, _skel, link);
                        self.skb_bundles.lock().unwrap().insert(ifindex, bundle);
                    }
                    Err(e) => {
                        tracing::warn!("SKB XDP attach for ifindex={ifindex} failed: {e}");
                    }
                }
            }
            None => {
                // WR is not active — store the skeleton as pending without
                // attaching, so it can be used if WR starts later.
                self.skb_pending.lock().unwrap().insert(ifindex, pending);
            }
        }
    }

    pub(crate) fn take_skb_pending(&self, ifindex: u32) -> Option<SkbPending> {
        self.skb_pending.lock().unwrap().remove(&ifindex)
    }

    fn create_wan_root(&self, ifindex: u32) -> LdEbpfResult<ChainRoot> {
        let builder = XdpWanRootSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_root")?;

        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &self.paths.xdp_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &self.paths.xdp_pipe_exits_lan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &self.paths.xdp_pipe_exits_wan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &self.paths.xdp_lan_pipe_root_progs_path(),
        )?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_wan_root")?;

        let root_prog_fd = skel.progs.xdp_wan_root.as_fd().as_raw_fd();
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
        let builder = XdpLanRootSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_root")?;

        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &self.paths.xdp_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &self.paths.xdp_pipe_exits_lan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &self.paths.xdp_pipe_exits_wan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &self.paths.xdp_lan_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &self.paths.xdp_redirect_able)?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_root")?;

        let root_prog_fd = skel.progs.xdp_lan_root.as_fd().as_raw_fd();
        let root_next_fd = skel.maps.root_next_stage.as_fd().as_raw_fd();

        self._seed.maps.xdp_lan_pipe_root_progs.update(
            &ifindex.to_ne_bytes(),
            &root_prog_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;

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

        for entry in state.stages.values() {
            delete_prog_array_fd(entry.next_stage_map_fd, dir_slot);
        }
        delete_prog_array_fd(root.root_next_stage_fd(), 0);

        let sorted: Vec<&StageEntry> = state
            .stages
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
}
