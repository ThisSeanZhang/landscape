//! Runtime-wide chain hub.
//!
//! Created once at runtime init, the hub owns everything that is interface-
//! level (rather than per-link):
//!
//! - the seed maps (prog arrays + dispatch maps) and their boot-time
//!   cleanup, plus the seed skeletons holding their handles,
//! - the TC exit skeletons (registered once into the shared exit arrays),
//! - the XDP wan-intro dispatch program (attached by the WAN route service),
//! - the process-global XDP LAN/WAN exit programs and their shared slots,
//! - the SKB-mode XDP fallback skeleton pool for PPPoE,
//! - the registry of logical [`LinkChain`]s keyed by chain id, driven by the
//!   link service lifecycle. Multiple logical chains may share one device.

use std::collections::HashMap;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};

use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType, Program, Xdp, XdpFlags};

use crate::bpf_ctx;
use crate::bpf_error::{LandscapeEbpfError, LdEbpfResult};
use crate::bpf_rs_shared::xdp_skb_pppoe_skel;
use crate::chain::link_chain::LinkChain;
use crate::landscape::{pin_and_reuse_map, OwnedOpenObject};
use crate::runtime::EbpfRuntime;
use crate::LandscapeMapPath;

pub(crate) mod xdp_wan_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_intro.skel.rs"));
}
mod tc_wan_ingress_exit_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_ingress_exit.skel.rs"));
}
mod tc_wan_egress_exit_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_wan_egress_exit.skel.rs"));
}
mod xdp_lan_chain_exit_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_chain.skel.rs"));
}
mod xdp_wan_route_exit_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_route.skel.rs"));
}

use tc_wan_egress_exit_skel::TcWanEgressExitSkelBuilder;
use tc_wan_ingress_exit_skel::TcWanIngressExitSkelBuilder;
use xdp_lan_chain_exit_skel::XdpLanChainSkelBuilder;
use xdp_wan_intro_skel::XdpWanIntroSkelBuilder;
use xdp_wan_route_exit_skel::XdpWanRouteSkelBuilder;

fn clear_map_entries(map: &libbpf_rs::MapMut<'_>) {
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        let _ = map.delete(&key);
    }
}

fn clear_pinned_map_entries(path: &std::path::Path) {
    let Ok(map) = libbpf_rs::MapHandle::from_pinned_path(path) else {
        return;
    };
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        let _ = map.delete(&key);
    }
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

// ─────────────────────────────────────────────────────────────────────────
// Native XDP attach (DRV mode), with SKB-mode fallback
// ─────────────────────────────────────────────────────────────────────────

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
        if let Some(old_bundle) = rt.hub.take_skb_bundle(ifindex) {
            let SkbXdpBundle { _link: _, _skel, _backing } = old_bundle;
            rt.hub.set_skb_pending(ifindex, SkbPending::new(_backing, _skel));
        }

        let result = Self::try_native(rt.clone(), prog, ifindex_i32);

        match result {
            Ok(link) => {
                // Native XDP succeeded — the pending SKB skeleton remains
                // in the hub untouched.
                Ok(link)
            }
            Err(e) => {
                // Native XDP failed — consume the pending SKB skeleton
                // (if any) and attach it as a fallback.
                if let Some(pending) = rt.hub.take_skb_pending(ifindex) {
                    let SkbPending { _skel, _backing } = pending;
                    match SkbXdpLink::attach(&_skel.progs.xdp_skb_pppoe, ifindex) {
                        Ok(skb_link) => {
                            let bundle = SkbXdpBundle::new(_backing, _skel, skb_link);
                            rt.hub.set_skb_bundle(ifindex, bundle);
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

impl Drop for NativeXdpLink {
    fn drop(&mut self) {
        Self::detach(self.ifindex, self.prog_fd);
        // If native XDP had failed and SKB was running as fallback,
        // detach it and recycle the skeleton back as pending for reuse.
        if let Some(old_bundle) = self.rt.hub.take_skb_bundle(self.ifindex as u32) {
            let SkbXdpBundle { _link: _, _skel, _backing } = old_bundle;
            self.rt.hub.set_skb_pending(self.ifindex as u32, SkbPending::new(_backing, _skel));
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
/// interface.  PPPoE prepares one of these and hands it to the hub.
/// The hub decides whether to attach it (as SKB fallback) or keep it
/// for later, depending on native XDP availability.
pub(crate) struct SkbPending {
    _skel: xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>,
    _backing: OwnedOpenObject,
}

impl SkbPending {
    pub(crate) fn new(
        backing: OwnedOpenObject,
        skel: xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>,
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
    _skel: xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>,
    _backing: OwnedOpenObject,
}

impl SkbXdpBundle {
    pub(crate) fn new(
        backing: OwnedOpenObject,
        skel: xdp_skb_pppoe_skel::XdpSkbPppoeSkel<'static>,
        link: SkbXdpLink,
    ) -> Self {
        Self { _backing: backing, _skel: skel, _link: link }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// ChainHub
// ─────────────────────────────────────────────────────────────────────────

pub struct ChainHub {
    pub(crate) paths: Arc<LandscapeMapPath>,
    seed: xdp_wan_intro_skel::XdpWanIntroSkel<'static>,
    _seed_backing: OwnedOpenObject,
    _exit_wi: tc_wan_ingress_exit_skel::TcWanIngressExitSkel<'static>,
    _exit_we: tc_wan_egress_exit_skel::TcWanEgressExitSkel<'static>,
    _back_wi: OwnedOpenObject,
    _back_we: OwnedOpenObject,
    _xdp_lan_exit: xdp_lan_chain_exit_skel::XdpLanChainSkel<'static>,
    _xdp_lan_exit_backing: OwnedOpenObject,
    _xdp_wan_exit: xdp_wan_route_exit_skel::XdpWanRouteSkel<'static>,
    _xdp_wan_exit_backing: OwnedOpenObject,
    /// Logical chains are keyed by their immutable chain id.  Several
    /// logical chains may share one physical ifindex.
    chains: Mutex<HashMap<u16, Arc<LinkChain>>>,
    skb_bundles: Mutex<HashMap<u32, SkbXdpBundle>>,
    skb_pending: Mutex<HashMap<u32, SkbPending>>,
}

impl ChainHub {
    /// Create the TC/XDP chain pin directories, seed every chain map, load
    /// the seed skeletons (XDP intro dispatch + TC exits) and clear stale
    /// entries left by previous runs. Called once at runtime init.
    pub fn init(paths: Arc<LandscapeMapPath>) -> LdEbpfResult<Arc<Self>> {
        let tc_chain_base = paths.tc_chain_base();
        std::fs::create_dir_all(&tc_chain_base).map_err(|e| LandscapeEbpfError::Context {
            context: format!("can not create tc chain dir {}", tc_chain_base.display()),
            source: e.into(),
        })?;

        // ── 1. Create and pin all TC seed PROG_ARRAY / HASH maps ──

        create_pinned_prog_array(&paths.tc_pipe_root_progs_path(), 1024)?;
        create_pinned_map(&paths.tc_wan_intro_dispatch_path(), MapType::Hash, 16, 4, 1024)?;
        create_pinned_prog_array(&paths.tc_pipe_exits_wan_ingress_path(), 1)?;
        create_pinned_prog_array(&paths.tc_pipe_exits_wan_egress_path(), 1)?;
        create_pinned_prog_array(&paths.tc_wan_egress_roots_path(), 1024)?;

        // ── 2. Load TC exit skeletons and inject their program FDs ──

        let (exit_wi, back_wi) = Self::init_exit_wan_ingress(&paths)?;
        let (exit_we, back_we) = Self::init_exit_wan_egress(&paths)?;

        // ── 3. XDP seed: pin dir, load wan-intro skeleton, clear stale ──

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
        // The TC dispatch map is pinned by the tc_wan_route loader rather
        // than the seed skeleton; apply the same previous-run cleanup to any
        // pin that already exists.
        clear_pinned_map_entries(&paths.tc_wan_intro_dispatch_path());

        // These are runtime-global exits, not per-link programs.  Keep both
        // skeletons alive for the lifetime of the hub and install their FDs
        // once into slot 0.  The existing skeletons are reused here so the
        // BPF implementation remains shared with the chain/route paths.
        let (xdp_lan_exit, xdp_lan_exit_backing) = Self::init_xdp_lan_exit(&paths)?;
        let (xdp_wan_exit, xdp_wan_exit_backing) = Self::init_xdp_wan_exit(&paths)?;

        Ok(Arc::new(Self {
            paths,
            seed: skel,
            _seed_backing: backing,
            _exit_wi: exit_wi,
            _exit_we: exit_we,
            _back_wi: back_wi,
            _back_we: back_we,
            _xdp_lan_exit: xdp_lan_exit,
            _xdp_lan_exit_backing: xdp_lan_exit_backing,
            _xdp_wan_exit: xdp_wan_exit,
            _xdp_wan_exit_backing: xdp_wan_exit_backing,
            chains: Mutex::new(HashMap::new()),
            skb_bundles: Mutex::new(HashMap::new()),
            skb_pending: Mutex::new(HashMap::new()),
        }))
    }

    fn init_xdp_lan_exit(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(xdp_lan_chain_exit_skel::XdpLanChainSkel<'static>, OwnedOpenObject)> {
        let builder = XdpLanChainSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open global xdp_lan_chain exit")?;

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
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able),
            "global xdp_lan_chain exit pin xdp_redirect_able"
        )?;

        let skel = bpf_ctx!(open_skel.load(), "load global xdp_lan_chain exit")?;
        let exit_fd = skel.progs.xdp_lan_chain_exit.as_fd().as_raw_fd();
        skel.maps.xdp_pipe_exits_lan.update(
            &0u32.to_ne_bytes(),
            &exit_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok((skel, backing))
    }

    fn init_xdp_wan_exit(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(xdp_wan_route_exit_skel::XdpWanRouteSkel<'static>, OwnedOpenObject)> {
        let builder = XdpWanRouteSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open global xdp_wan_route exit")?;

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
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able),
            "global xdp_wan_route exit pin xdp_redirect_able"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &paths.wan_ip),
            "global xdp_wan_route exit pin wan_ip_binding"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
            "global xdp_wan_route exit pin rt4_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
            "global xdp_wan_route exit pin rt6_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_slot_map, &paths.rt4_slot_map),
            "global xdp_wan_route exit pin rt4_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_slot_map, &paths.rt6_slot_map),
            "global xdp_wan_route exit pin rt6_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
            "global xdp_wan_route exit pin flow4_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
            "global xdp_wan_route exit pin flow6_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
            "global xdp_wan_route exit pin flow4_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
            "global xdp_wan_route exit pin flow6_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
            "global xdp_wan_route exit pin rt4_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
            "global xdp_wan_route exit pin rt6_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
            "global xdp_wan_route exit pin flow_match_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
            "global xdp_wan_route exit pin ip_mac_v4"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
            "global xdp_wan_route exit pin ip_mac_v6"
        )?;

        let skel = bpf_ctx!(open_skel.load(), "load global xdp_wan_route exit")?;
        let exit_fd = skel.progs.xdp_wan_route_ingress.as_fd().as_raw_fd();
        skel.maps.xdp_pipe_exits_wan.update(
            &0u32.to_ne_bytes(),
            &exit_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok((skel, backing))
    }

    fn init_exit_wan_ingress(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(tc_wan_ingress_exit_skel::TcWanIngressExitSkel<'static>, OwnedOpenObject)>
    {
        let builder = TcWanIngressExitSkelBuilder::default();
        let (back, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open tc_wan_ingress_exit skeleton")?;
        crate::maps::reuse_pinned_map_or_recreate(
            &mut open_skel.maps.tc_pipe_exits_wan_ingress,
            &paths.tc_pipe_exits_wan_ingress_path(),
        );
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow_match_map, &paths.flow_match_map),
            "tc_wan_ingress_exit pin flow_match_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.wan_ip_binding, &paths.wan_ip),
            "tc_wan_ingress_exit pin wan_ip_binding"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_lan_map, &paths.rt4_lan_map),
            "tc_wan_ingress_exit pin rt4_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_lan_map, &paths.rt6_lan_map),
            "tc_wan_ingress_exit pin rt6_lan_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_slot_map, &paths.rt4_slot_map,),
            "tc_wan_ingress_exit pin rt4_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_slot_map, &paths.rt6_slot_map,),
            "tc_wan_ingress_exit pin rt6_slot_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_dns_map, &paths.flow4_dns_map),
            "tc_wan_ingress_exit pin flow4_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_dns_map, &paths.flow6_dns_map),
            "tc_wan_ingress_exit pin flow6_dns_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow4_ip_map, &paths.flow4_ip_map),
            "tc_wan_ingress_exit pin flow4_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.flow6_ip_map, &paths.flow6_ip_map),
            "tc_wan_ingress_exit pin flow6_ip_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt4_cache_map, &paths.rt4_cache_map),
            "tc_wan_ingress_exit pin rt4_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.rt6_cache_map, &paths.rt6_cache_map),
            "tc_wan_ingress_exit pin rt6_cache_map"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v4, &paths.ip_mac_v4),
            "tc_wan_ingress_exit pin ip_mac_v4"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.ip_mac_v6, &paths.ip_mac_v6),
            "tc_wan_ingress_exit pin ip_mac_v6"
        )?;
        crate::bpf_ctx!(
            pin_and_reuse_map(&mut open_skel.maps.xdp_redirect_able, &paths.xdp_redirect_able),
            "tc_wan_ingress_exit pin xdp_redirect_able"
        )?;
        let skel = bpf_ctx!(open_skel.load(), "load tc_wan_ingress_exit skeleton")?;
        let exit_fd = skel.progs.tc_wan_ingress_exit_redirect.as_fd().as_raw_fd();
        skel.maps.tc_pipe_exits_wan_ingress.update(
            &0u32.to_ne_bytes(),
            &exit_fd.to_ne_bytes(),
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

    // ── Chain registry ──────────────────────────────────────────────────

    /// Open (or reuse) the stage-chain for `link_chain_id`, creating and
    /// registering its XDP + TC roots, driven by the link lifecycle.
    pub fn open_link_chain(
        self: &Arc<Self>,
        ifindex: u32,
        has_mac: bool,
        link_chain_id: u16,
    ) -> LdEbpfResult<Arc<LinkChain>> {
        if link_chain_id == 0 {
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: "cannot open unassigned link chain id".to_string(),
                source: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            });
        }
        let (chain, created) = {
            let mut chains = self.chains.lock().unwrap();
            match chains.get(&link_chain_id) {
                Some(chain) => (chain.clone(), false),
                None => {
                    let chain = LinkChain::create(self.clone(), ifindex, link_chain_id)?;
                    chains.insert(link_chain_id, chain.clone());
                    (chain, true)
                }
            }
        };
        if chain.physical_ifindex() != ifindex {
            if created {
                self.close_if_current(&chain);
            }
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: format!(
                    "chain id {} is already bound to ifindex {}, not {}",
                    link_chain_id,
                    chain.physical_ifindex(),
                    ifindex
                ),
                source: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            });
        }
        if let Err(err) = chain.open_roots(has_mac, link_chain_id) {
            if created {
                self.close_if_current(&chain);
            }
            return Err(err);
        }
        Ok(chain)
    }

    /// Get the stage-chain for `link_chain_id`, creating an empty one if none is
    /// open yet (stage attach path: roots are then created lazily).
    ///
    /// Returns an error (instead of panicking) for an unassigned chain id so a
    /// bad config degrades into a per-service error rather than taking the
    /// daemon down.
    pub fn get_or_create_chain(
        self: &Arc<Self>,
        link_chain_id: u16,
        ifindex: u32,
    ) -> LdEbpfResult<Arc<LinkChain>> {
        if link_chain_id == 0 {
            return Err(crate::bpf_error::LandscapeEbpfError::Context {
                context: "cannot attach a stage to unassigned link chain id 0".to_string(),
                source: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
            });
        }
        let mut chains = self.chains.lock().unwrap();
        match chains.get(&link_chain_id) {
            Some(chain) => {
                if chain.physical_ifindex() != ifindex {
                    return Err(crate::bpf_error::LandscapeEbpfError::Context {
                        context: format!(
                            "chain id {} is bound to ifindex {}, not {}",
                            link_chain_id,
                            chain.physical_ifindex(),
                            ifindex
                        ),
                        source: libbpf_rs::Error::from_raw_os_error(libc::EINVAL),
                    });
                }
                Ok(chain.clone())
            }
            None => {
                let chain = LinkChain::create(self.clone(), ifindex, link_chain_id)?;
                chains.insert(link_chain_id, chain.clone());
                Ok(chain)
            }
        }
    }

    /// Close `chain` only if it is still the current registry generation for
    /// its chain id.  This prevents a delayed guard from closing a newer
    /// chain opened after the original guard was dropped.
    pub fn close_if_current(&self, chain: &Arc<LinkChain>) {
        let mut chains = self.chains.lock().unwrap();
        let Some(current) = chains.get(&chain.link_chain_id()).cloned() else {
            return;
        };
        if !Arc::ptr_eq(&current, chain) {
            return;
        }
        // Keep the registry lock while tearing down map entries.  Otherwise
        // a new generation could be inserted between removal and cleanup and
        // the old generation would delete the new generation's map slots.
        current.close();
        chains.remove(&chain.link_chain_id());
    }

    // ── XDP intro / exit ────────────────────────────────────────────────

    /// The seed skeleton's wan-intro dispatch program, for callers attaching
    /// a [`NativeXdpLink`].
    pub(crate) fn wan_intro_prog(&self) -> &Program<'_> {
        &self.seed.progs.wan_intro_dispatch
    }

    pub(crate) fn xdp_seed(&self) -> &xdp_wan_intro_skel::XdpWanIntroSkel<'static> {
        &self.seed
    }

    // ── SKB fallback pool ───────────────────────────────────────────────

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
                match SkbXdpLink::attach(&_skel.progs.xdp_skb_pppoe, ifindex) {
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
}
