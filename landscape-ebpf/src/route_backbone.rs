//! Route backbone: the link-independent dispatch substrate shared by the
//! LAN/WAN route services and every WAN link chain.
//!
//! Everything here is process-lifetime and shared by **all** links:
//!
//! * the global [`WanTrieDispatcher`] (dest IP / PPPoE session → chain id,
//!   the sole dispatch authority) plus the intro seed skeleton that carries
//!   its arena and pins the shared root prog arrays;
//! * the shared exit skeletons pinned into the per-direction exit maps
//!   (the chains' terminal tail-call targets are route programs);
//! * creation of the pinned prog-array maps every chain registers into.
//!
//! The root arrays are the route↔chain contract surface: their *shell*
//! lives here (pinned at boot), their *content* is written by per-link
//! [`crate::chain::wan_link`] chains.  Per-iface XDP slot arbitration
//! lives in [`crate::xdp_attach::XdpAttach`].

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Arc;

use libbpf_rs::MapCore;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use libbpf_rs::MapType;
use libbpf_rs::OpenMapMut;
use libbpf_rs::Program;
use libbpf_rs::libbpf_sys;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;

use crate::LandscapeMapPath;
use crate::bpf_ctx;
use crate::bpf_error::LandscapeEbpfError;
use crate::bpf_error::LdEbpfResult;
use crate::landscape::OwnedOpenObject;
use crate::landscape::pin_and_reuse_map;
use crate::maps::wan_trie::dispatcher::WanTrieDispatcher;
use crate::maps::wan_trie::dispatcher::cast_arena_tbl;

/// Shared with `crate::maps` (wan binding writes go through this
/// skeleton's pinned map types).
use crate::skel::tc_wan_egress_exit::TcWanEgressExitSkelBuilder;
use crate::skel::tc_wan_ingress_route::TcWanIngressRouteSkelBuilder;
use crate::skel::xdp_lan_exit::XdpLanExitSkelBuilder;
use crate::skel::xdp_wan_intro::XdpWanIntroSkelBuilder;
use crate::skel::xdp_wan_route::XdpWanRouteSkelBuilder;

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

pub(crate) fn pinned_map(path: &Path) -> LdEbpfResult<MapHandle> {
    MapHandle::from_pinned_path(path).map_err(|e| crate::bpf_error::LandscapeEbpfError::Context {
        context: format!("open pinned map {}", path.display()),
        source: e,
    })
}

fn clear_map_entries(map: &libbpf_rs::MapMut<'_>) {
    let keys: Vec<Vec<u8>> = map.keys().collect();
    for key in keys {
        let _ = map.delete(&key);
    }
}

pub struct RouteBackbone {
    paths: Arc<LandscapeMapPath>,
    /// The one global WAN dispatch-trie controller: owns the
    /// authoritative entry set and publishes through the seed arena that
    /// every intro program shares.
    trie: Arc<WanTrieDispatcher>,
    // TrieTarget: the guard field drops before the skeleton field, so the
    // trie target is detached while the arena mmap is still alive.
    _seed: crate::maps::wan_trie::dispatcher::TrieTarget<
        crate::skel::xdp_wan_intro::XdpWanIntroSkel<'static>,
    >,
    _backing: OwnedOpenObject,
    _exit_lan_skel: crate::skel::xdp_lan_exit::XdpLanExitSkel<'static>,
    _exit_lan_backing: OwnedOpenObject,
    _exit_wan_skel: crate::skel::xdp_wan_route::XdpWanRouteSkel<'static>,
    _exit_wan_backing: OwnedOpenObject,
    _route_wi: crate::skel::tc_wan_ingress_route::TcWanIngressRouteSkel<'static>,
    _back_wi: OwnedOpenObject,
    _exit_we: crate::skel::tc_wan_egress_exit::TcWanEgressExitSkel<'static>,
    _back_we: OwnedOpenObject,
}

impl RouteBackbone {
    /// Create both pin spaces, seed their shared prog-array maps, clear
    /// stale entries left by previous runs, and load the intro/exit
    /// skeletons that every link shares.
    pub(crate) fn new(
        paths: Arc<LandscapeMapPath>,
        wan_trie: Arc<WanTrieDispatcher>,
    ) -> LdEbpfResult<Self> {
        // ── XDP half ──
        std::fs::create_dir_all(&paths.xdp_base).map_err(|e| LandscapeEbpfError::Context {
            context: format!("can not create xdp base dir {}", paths.xdp_base.display()),
            source: e.into(),
        })?;

        // Legacy pin of the pre-trie dispatch hash map: nothing reads it
        // anymore, so reclaim the bpffs entry if a previous run left one.
        let _ = std::fs::remove_file(paths.xdp_base.join("wan_intro_dispatch"));

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
        let mut skel = bpf_ctx!(open_skel.load(), "load xdp seed skeleton")?;

        // Register the seed's dispatch-trie arena with the global
        // dispatcher: publishes the current (empty) entry set, so the
        // program is never attached over a stale or zeroed table. A
        // failure aborts manager creation for the same reason.
        let wan_trie_guard = {
            let data = skel.maps.wan_trie_arena_data.as_mut().expect("wan_trie arena mmap data");
            wan_trie.register(cast_arena_tbl(&mut data.wan_trie_tbl))?
        };

        // No chains exist in this process yet, so any entry left in these
        // maps belongs to a previous run (crash or kill). Dropping them lets
        // the kernel finally unload the orphaned root/exit programs.
        clear_map_entries(&skel.maps.xdp_pipe_root_progs);
        clear_map_entries(&skel.maps.xdp_lan_pipe_root_progs);
        clear_map_entries(&skel.maps.xdp_pipe_exits_lan);
        clear_map_entries(&skel.maps.xdp_pipe_exits_wan);

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

        // ── TC half ──
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
            trie: wan_trie,
            _seed: crate::maps::wan_trie::dispatcher::TrieTarget::from_parts(wan_trie_guard, skel),
            _backing: backing,
            _exit_lan_skel: exit_lan_skel,
            _exit_lan_backing: exit_lan_backing,
            _exit_wan_skel: exit_wan_skel,
            _exit_wan_backing: exit_wan_backing,
            _route_wi: route_wi,
            _back_wi: back_wi,
            _exit_we: exit_we,
            _back_we: back_we,
        })
    }

    /// Bind another program's `wan_trie_arena` to the seed's shared arena.
    pub(crate) fn reuse_wan_trie_map(&self, map: &mut OpenMapMut<'_>) -> LdEbpfResult<()> {
        let fd = self._seed.skel.maps.wan_trie_arena.as_fd();
        map.reuse_fd(fd).map_err(|source| LandscapeEbpfError::Context {
            context: "reuse shared wan_trie_arena fd failed".to_string(),
            source,
        })
    }

    fn load_lan_exit()
    -> LdEbpfResult<(crate::skel::xdp_lan_exit::XdpLanExitSkel<'static>, OwnedOpenObject)> {
        let builder = XdpLanExitSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_exit skeleton")?;
        let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_exit skeleton")?;
        Ok((skel, backing))
    }

    fn load_wan_exit(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(crate::skel::xdp_wan_route::XdpWanRouteSkel<'static>, OwnedOpenObject)> {
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

    fn init_wan_ingress_route(
        paths: &LandscapeMapPath,
    ) -> LdEbpfResult<(
        crate::skel::tc_wan_ingress_route::TcWanIngressRouteSkel<'static>,
        OwnedOpenObject,
    )> {
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
    ) -> LdEbpfResult<(
        crate::skel::tc_wan_egress_exit::TcWanEgressExitSkel<'static>,
        OwnedOpenObject,
    )> {
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

    pub(crate) fn paths(&self) -> &Arc<LandscapeMapPath> {
        &self.paths
    }

    /// The global WAN dispatch-trie controller shared by all links.
    pub(crate) fn trie(&self) -> &Arc<WanTrieDispatcher> {
        &self.trie
    }

    /// The seed skeleton's wan-intro dispatch program, for callers
    /// attaching a native XDP link (via
    /// [`crate::xdp_attach::XdpAttach::attach_native`]).
    pub(crate) fn wan_intro_prog(&self) -> &Program<'_> {
        &self._seed.skel.progs.xdp_wan_intro
    }

    /// Register a freshly loaded XDP from-WAN root prog fd under the
    /// link's chain id in the shared root prog array.
    pub(crate) fn register_xdp_wan_root(&self, chain: u16, root_prog_fd: i32) -> LdEbpfResult<()> {
        self._seed.skel.maps.xdp_pipe_root_progs.update(
            &(chain as u32).to_ne_bytes(),
            &root_prog_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok(())
    }

    /// Register a freshly loaded XDP from-LAN root prog fd under the
    /// link's chain id in the shared lan-pipe root prog array.
    pub(crate) fn register_xdp_lan_root(&self, chain: u16, root_prog_fd: i32) -> LdEbpfResult<()> {
        self._seed.skel.maps.xdp_lan_pipe_root_progs.update(
            &(chain as u32).to_ne_bytes(),
            &root_prog_fd.to_ne_bytes(),
            MapFlags::ANY,
        )?;
        Ok(())
    }

    /// Remove the link's chain id from both shared XDP root prog arrays.
    pub(crate) fn unregister_xdp_roots(&self, chain: u16) {
        let slot = (chain as u32).to_ne_bytes();
        let _ = self._seed.skel.maps.xdp_pipe_root_progs.delete(&slot);
        let _ = self._seed.skel.maps.xdp_lan_pipe_root_progs.delete(&slot);
    }
}
