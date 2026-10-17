//! Shared test infrastructure usable by every test-* feature tier.
//!
//! Everything here depends only on runtime skeletons (via `crate::skel`) or
//! plain libraries, so it compiles under bare `test-support` and is never
//! gated on a specific topic feature.
//!
//! - [`check`]: packet output analysis / assertions
//! - [`map`]: map seeding helpers + pinned shared-map handles
//! - [`net`]: network namespace / veth utilities
//! - [`skb`]: `__sk_buff` mirror (`TestSkb`)
//! - [`wire`]: mirror types for test-only eBPF output snapshots + layout tests
// Helper items are consumed by topic tests that may be compiled out in a
// partial build; only the full `bpf-test` build enforces dead-code hygiene.
#![cfg_attr(not(feature = "bpf-test"), allow(dead_code, unused_imports))]

pub(crate) mod check;
/// Map seeding / assertion helpers (ex `tests/route/map_helper.rs`).
pub(crate) mod map;
/// Network namespace / veth utilities (ex `tests/net_utils.rs`).
pub(crate) mod net;
/// `__sk_buff` mirror and skb packet payloads (ex `tests/mod.rs`).
pub(crate) mod skb;
/// Mirror types for test-only eBPF output snapshots plus their
/// layout-consistency tests (ex `tests/wire.rs`).
pub(crate) mod wire;

pub(crate) use crate::test_support::isolated_pin_root;

pub(crate) use map::init_shared_maps_for_test;
pub(crate) use net::check_ifindex;

use std::sync::atomic::{AtomicU32, Ordering};

static TEST_ID: AtomicU32 = AtomicU32::new(0);

/// Monotonic per-test id (e.g. for ifindex / netns naming).
pub(crate) fn test_id() -> u32 {
    TEST_ID.fetch_add(1, Ordering::Relaxed)
}
