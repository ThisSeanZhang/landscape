//! XDP half of the per-link chain: from-WAN / from-LAN root programs,
//! per-direction stage tables, and the loader-facing view
//! ([`XdpChainView`]) used by the XDP stage loaders.

use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

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

use super::WanLinkDataplane;

mod xdp_wan_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_root.skel.rs"));
}
mod xdp_lan_root_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_root.skel.rs"));
}

use xdp_lan_root_skel::XdpLanRootSkelBuilder;
use xdp_wan_root_skel::XdpWanRootSkelBuilder;

// ── XDP half ──

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

#[derive(Default)]
pub(super) struct XdpChainState {
    // from-WAN direction (WAN→LAN), root of xdp_wan_root
    pub(super) wan_root: Option<ChainRoot>,
    // from-LAN direction (LAN→WAN), root of xdp_lan_root
    pub(super) lan_root: Option<ChainRoot>,
    pub(super) lan_stages: StageTable<FromLanStageType>,
    pub(super) wan_stages: StageTable<FromWanStageType>,
}

// Family-indexed link_chain_id slots; must match link_chain_id/xdp_stage.h and
// link_chain_id/xdp_cb.h (next_stage slots are direction x family, root
// slots are family-only).
const XDP_FROM_LAN_SLOT_V4: u32 = 0;
const XDP_FROM_LAN_SLOT_V6: u32 = 1;
const XDP_FROM_WAN_SLOT_V4: u32 = 2;
const XDP_FROM_WAN_SLOT_V6: u32 = 3;
const XDP_ROOT_SLOT_V4: u32 = 0;
const XDP_ROOT_SLOT_V6: u32 = 1;

pub(super) enum ChainRoot {
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

impl WanLinkDataplane {
    fn relink_xdp(&self, dir: ChainDir) -> LdEbpfResult<()> {
        let inner = self.inner.lock().unwrap();
        if inner.closed {
            tracing::warn!(chain = self.id, "relink on closed wan link dataplane");
            return Ok(());
        }
        let state = &inner.xdp;
        match dir {
            ChainDir::Wan => relink_family_stages(
                state.wan_root.as_ref().unwrap().root_next_stage_fd(),
                &state.wan_stages,
                XDP_ROOT_SLOT_V4,
                XDP_ROOT_SLOT_V6,
                XDP_FROM_WAN_SLOT_V4,
                XDP_FROM_WAN_SLOT_V6,
            ),
            ChainDir::Lan => relink_family_stages(
                state.lan_root.as_ref().unwrap().root_next_stage_fd(),
                &state.lan_stages,
                XDP_ROOT_SLOT_V4,
                XDP_ROOT_SLOT_V6,
                XDP_FROM_LAN_SLOT_V4,
                XDP_FROM_LAN_SLOT_V6,
            ),
        }
    }

    pub(super) fn create_wan_root(
        backbone: &RouteBackbone,
        link_chain_id: u16,
    ) -> LdEbpfResult<ChainRoot> {
        let builder = XdpWanRootSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_wan_root")?;

        open_skel.maps.rodata_data.as_deref_mut().unwrap().current_chain = link_chain_id as u32;

        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &backbone.paths().xdp_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &backbone.paths().xdp_pipe_exits_lan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &backbone.paths().xdp_pipe_exits_wan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &backbone.paths().xdp_lan_pipe_root_progs_path(),
        )?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_wan_root")?;

        let root_prog_fd = skel.progs.xdp_wan_root.as_fd().as_raw_fd();
        let root_next_fd = skel.maps.root_next_stage.as_fd().as_raw_fd();

        backbone.register_xdp_wan_root(link_chain_id, root_prog_fd)?;

        Ok(ChainRoot::Wan {
            _skel: skel,
            _backing: backing,
            root_next_stage_fd: root_next_fd,
        })
    }

    /// The from-LAN direction root of the WAN link owning `link_chain_id`: an
    /// xdp_lan_root instance (never attached) registered under the link's
    /// link id in xdp_lan_pipe_root_progs.
    pub(super) fn create_lan_side_root(
        backbone: &RouteBackbone,
        link_chain_id: u16,
    ) -> LdEbpfResult<ChainRoot> {
        let builder = XdpLanRootSkelBuilder::default();
        let (backing, obj) = OwnedOpenObject::new();
        let mut open_skel = bpf_ctx!(builder.open(obj), "open xdp_lan_root")?;

        open_skel.maps.rodata_data.as_deref_mut().unwrap().current_chain = link_chain_id as u32;

        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_root_progs,
            &backbone.paths().xdp_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_lan,
            &backbone.paths().xdp_pipe_exits_lan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_pipe_exits_wan,
            &backbone.paths().xdp_pipe_exits_wan_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_lan_pipe_root_progs,
            &backbone.paths().xdp_lan_pipe_root_progs_path(),
        )?;
        pin_and_reuse_map(
            &mut open_skel.maps.xdp_redirect_able,
            &backbone.paths().xdp_redirect_able,
        )?;

        let skel = bpf_ctx!(open_skel.load(), "load xdp_lan_root")?;

        let root_prog_fd = skel.progs.xdp_lan_root.as_fd().as_raw_fd();
        let root_next_fd = skel.maps.root_next_stage.as_fd().as_raw_fd();

        backbone.register_xdp_lan_root(link_chain_id, root_prog_fd)?;

        Ok(ChainRoot::Lan {
            _skel: skel,
            _backing: backing,
            root_next_stage_fd: root_next_fd,
        })
    }
}

/// XDP-side view used by the stage loaders.
pub(crate) struct XdpChainView<'a> {
    dp: &'a WanLinkDataplane,
}

impl<'a> XdpChainView<'a> {
    pub(super) fn new(dp: &'a WanLinkDataplane) -> Self {
        Self { dp }
    }
}

impl XdpChainView<'_> {
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
        inner.xdp.wan_stages.insert((stage, family), prog);
        drop(inner);
        self.dp.relink_xdp(ChainDir::Wan)
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
        inner.xdp.lan_stages.insert((stage, family), prog);
        drop(inner);
        self.dp.relink_xdp(ChainDir::Lan)
    }

    pub(crate) fn remove_from_wan(&self, stage: FromWanStageType, family: StageFamily) {
        if !self.dp.guard_open() {
            return;
        }
        let removed = {
            let mut inner = self.dp.inner.lock().unwrap();
            inner.xdp.wan_stages.remove(&(stage, family)).is_some()
        };
        if removed {
            let _ = self.dp.relink_xdp(ChainDir::Wan);
        }
    }

    pub(crate) fn remove_from_lan(&self, stage: FromLanStageType, family: StageFamily) {
        if !self.dp.guard_open() {
            return;
        }
        let removed = {
            let mut inner = self.dp.inner.lock().unwrap();
            inner.xdp.lan_stages.remove(&(stage, family)).is_some()
        };
        if removed {
            let _ = self.dp.relink_xdp(ChainDir::Lan);
        }
    }
}
