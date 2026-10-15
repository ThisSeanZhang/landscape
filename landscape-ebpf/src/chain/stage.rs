//! Direction-specific chain stage taxonomy shared by the XDP and TC
//! chain managers, plus the per-family program descriptors and
//! PROGARRAY wiring helpers they link with.
//!
//! Chain identity is the side the packet was received FROM (not where it
//! is going), so every manager keeps one stage table per direction:
//!
//! * from-WAN chain — packets received on a WAN interface (the XDP wan
//!   chain and the TC WAN ingress chain);
//! * from-LAN chain — packets received from the LAN side (the XDP lan
//!   chain and the TC WAN egress chain, which carries LAN-forwarded and
//!   local-outbound traffic).
//!
//! The stage enums express chain ORDER only, never services: Nat is one
//! chain position whose two families are filled independently by the
//! nat4 and nat6 services (separate skeletons, separate lifecycles).  A
//! table row is therefore one family of one position — a [`StageTable`]
//! keyed by `(stage, family)` — and registration is a plain map
//! insert/remove: injecting nat4's v4 side never touches nat6's v6 side,
//! and a position leaves the chain when its last family row goes.
//!
//! Every row carries its own next-stage PROG_ARRAY fd because the
//! families of one position may come from different skeletons, each with
//! its own map the successor is linked into.

use std::collections::BTreeMap;

use libbpf_rs::libbpf_sys;

use crate::bpf_error::{LandscapeEbpfError, LdEbpfResult};

/// Stages of the from-WAN chain (packets received on a WAN interface).
/// Declaration order = chain order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum FromWanStageType {
    Mss = 0,
    Firewall = 1,
    Nat = 2,
}

/// Stages of the from-LAN chain (packets received from the LAN side).
/// Declaration order = chain order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum FromLanStageType {
    Mss = 0,
    Firewall = 1,
    Nat = 2,
    /// Per-link terminal encap stage; never on the from-WAN chain (the
    /// WAN side decapsulates at the intro dispatch), which is why the
    /// from-WAN enum has no such variant.
    Pppoe = 3,
}

/// The IP family one stage-table row belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum StageFamily {
    V4,
    V6,
}

impl StageFamily {
    /// Both families, for callers that register/unregister a whole
    /// dual-family stage at once.
    pub const ALL: [StageFamily; 2] = [StageFamily::V4, StageFamily::V6];
}

/// One family's contribution to a chain position: the family's entry
/// program fd plus the owning skeleton's next-stage PROG_ARRAY fd the
/// manager links the successor into.
#[derive(Clone, Copy, Debug)]
pub struct FamilyProg {
    pub prog_fd: i32,
    pub next_stage_map_fd: i32,
}

/// A direction's stage table: `(chain position, family) -> programs`.
/// Iteration order is position first, so filtering by family keeps that
/// family's chain order.
pub type StageTable<S> = BTreeMap<(S, StageFamily), FamilyProg>;

pub(crate) fn family_chain<S: Ord>(
    stages: &StageTable<S>,
    family: StageFamily,
) -> Vec<&FamilyProg> {
    stages.iter().filter(|((_, f), _)| *f == family).map(|(_, p)| p).collect()
}

pub(crate) fn update_prog_array_fd(map_fd: i32, key: u32, val: i32) -> LdEbpfResult<()> {
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
        return Err(LandscapeEbpfError::Context {
            context: format!("update_prog_array fd={} key={}", map_fd, key),
            source: libbpf_rs::Error::from_raw_os_error(-ret),
        });
    }
    Ok(())
}

pub(crate) fn delete_prog_array_fd(map_fd: i32, key: u32) {
    let k = key.to_ne_bytes();
    let _ =
        unsafe { libbpf_sys::bpf_map_delete_elem(map_fd, k.as_ptr() as *const std::ffi::c_void) };
}

/// Link one family's chain: root slot → the first entry program, then
/// each entry's own next-stage map (at `next_slot`) to its successor.
/// An empty family chain links nothing (the root-slot delete already
/// unlinked it for this direction).
fn link_family_chain(
    root_fd: i32,
    root_slot: u32,
    chain: &[&FamilyProg],
    next_slot: u32,
) -> LdEbpfResult<()> {
    let Some(first) = chain.first() else { return Ok(()) };
    update_prog_array_fd(root_fd, root_slot, first.prog_fd)?;
    for i in 0..chain.len() - 1 {
        update_prog_array_fd(chain[i].next_stage_map_fd, next_slot, chain[i + 1].prog_fd)?;
    }
    Ok(())
}

/// Rewire one chain direction from scratch: clear this direction's
/// slots in every registered next-stage map and the root's family
/// slots, then link both families through the table in chain order.
///
/// `next_slot_v4`/`next_slot_v6` are the slots the direction's stages
/// tail-call through — TC uses the family slots for both roots and
/// stages, XDP uses family slots for roots and direction x family slots
/// for stages.
pub(crate) fn relink_family_stages<S: Ord>(
    root_next_stage_fd: i32,
    stages: &StageTable<S>,
    root_slot_v4: u32,
    root_slot_v6: u32,
    next_slot_v4: u32,
    next_slot_v6: u32,
) -> LdEbpfResult<()> {
    // Dual-family stages register the same next-stage map under both
    // rows; the repeated deletes are idempotent.
    for prog in stages.values() {
        delete_prog_array_fd(prog.next_stage_map_fd, next_slot_v4);
        delete_prog_array_fd(prog.next_stage_map_fd, next_slot_v6);
    }
    delete_prog_array_fd(root_next_stage_fd, root_slot_v4);
    delete_prog_array_fd(root_next_stage_fd, root_slot_v6);

    let chain_v4 = family_chain(stages, StageFamily::V4);
    let chain_v6 = family_chain(stages, StageFamily::V6);
    link_family_chain(root_next_stage_fd, root_slot_v4, &chain_v4, next_slot_v4)?;
    link_family_chain(root_next_stage_fd, root_slot_v6, &chain_v6, next_slot_v6)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog(fd: i32) -> FamilyProg {
        FamilyProg { prog_fd: fd, next_stage_map_fd: fd + 100 }
    }

    fn table() -> StageTable<FromWanStageType> {
        // Inserted out of chain order on purpose: iteration must still
        // come out in chain order.
        let mut t = StageTable::new();
        t.insert((FromWanStageType::Nat, StageFamily::V4), prog(5));
        t.insert((FromWanStageType::Mss, StageFamily::V4), prog(1));
        t.insert((FromWanStageType::Firewall, StageFamily::V6), prog(4));
        t.insert((FromWanStageType::Mss, StageFamily::V6), prog(2));
        t.insert((FromWanStageType::Firewall, StageFamily::V4), prog(3));
        t
    }

    #[test]
    fn family_chain_preserves_chain_order() {
        let t = table();
        let v4: Vec<i32> = family_chain(&t, StageFamily::V4).iter().map(|p| p.prog_fd).collect();
        assert_eq!(v4, vec![1, 3, 5]);
        let v6: Vec<i32> = family_chain(&t, StageFamily::V6).iter().map(|p| p.prog_fd).collect();
        assert_eq!(v6, vec![2, 4]);
    }

    #[test]
    fn nat_families_register_independently() {
        let mut t = StageTable::<FromWanStageType>::new();
        t.insert((FromWanStageType::Nat, StageFamily::V4), prog(10));
        t.insert((FromWanStageType::Nat, StageFamily::V6), prog(20));
        assert_eq!(family_chain(&t, StageFamily::V4).len(), 1);
        assert_eq!(family_chain(&t, StageFamily::V6).len(), 1);

        t.insert((FromWanStageType::Nat, StageFamily::V4), prog(11));
        assert_eq!(family_chain(&t, StageFamily::V4)[0].prog_fd, 11);
        assert_eq!(family_chain(&t, StageFamily::V6)[0].prog_fd, 20);

        t.remove(&(FromWanStageType::Nat, StageFamily::V4));
        assert_eq!(family_chain(&t, StageFamily::V4).len(), 0);
        assert_eq!(family_chain(&t, StageFamily::V6).len(), 1);
    }

    #[test]
    fn pppoe_only_exists_on_the_from_lan_chain() {
        let mut lan = StageTable::<FromLanStageType>::new();
        lan.insert((FromLanStageType::Pppoe, StageFamily::V4), prog(1));
        lan.insert((FromLanStageType::Pppoe, StageFamily::V6), prog(2));
        assert_eq!(lan.len(), 2);
    }

    #[test]
    fn all_families_covers_both() {
        assert_eq!(StageFamily::ALL, [StageFamily::V4, StageFamily::V6]);
    }
}
