//! `wan_trie` map C anchor: `src/bpf/map/wan_trie.h` (real program skels).

use zerocopy::{FromBytes, Immutable, IntoBytes};

/// Node pool size per half; must match the header's `WAN_TRIE_POOL_NODES`.
pub(crate) const WAN_TRIE_POOL_NODES: usize = 2048;

/// One 256-way stride node: `child[byte >> 5][byte & 31]` stores
/// `node_index + 1` (0 = absent). Exactly 1024B so node addressing on the
/// BPF side is `idx << 10`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct WanTrieNode {
    pub child: [[u32; 32]; 8],
}

/// One half of the double-buffered table: `nodes` is the child pool,
/// `vals` the parallel value array. Arrays are chunked to <= 32 per
/// dimension so the generated skel's `Default` derive compiles; both sides
/// address them flat (BPF via pointer arithmetic, Rust via index helpers).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct WanTrieHalf {
    pub node_cnt: u32,
    pub nodes: [[[WanTrieNode; 32]; 32]; 2],
    pub vals: [[[u32; 32]; 32]; 2],
}

/// Double-buffered trie table: readers pick a half via `cur` (aligned u32
/// load/store is atomic on x86); the control plane fills the spare half,
/// then flips `cur` last.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct WanTrieTbl {
    pub cur: u32,
    pub pad: u32,
    pub halves: [WanTrieHalf; 2],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    /// Absolute layout pins, so a header edit that drifts a size/offset
    /// fails `cargo test` even without the bpf-test feature.
    #[test]
    fn wan_trie_layouts_are_pinned() {
        assert_eq!(size_of::<WanTrieNode>(), 1024);
        assert_eq!(offset_of!(WanTrieHalf, node_cnt), 0);
        assert_eq!(offset_of!(WanTrieHalf, nodes), 4);
        assert_eq!(size_of::<WanTrieHalf>(), 4 + WAN_TRIE_POOL_NODES * 1028);
        assert_eq!(offset_of!(WanTrieTbl, halves), 8);
        assert_eq!(size_of::<WanTrieTbl>(), 8 + 2 * (4 + WAN_TRIE_POOL_NODES * 1028));
    }

    /// Cross-check against the real generated skeleton types (the only
    /// consumer of the header today is the benchmark program).
    #[cfg(all(test, feature = "bpf-test"))]
    #[test]
    fn wan_trie_layouts_match_bench_skel() {
        use crate::bench::bench_wan_dispatch::types as skel;

        assert_size!(WanTrieNode, skel::wan_trie_node);
        assert_size!(WanTrieHalf, skel::wan_trie_half);
        assert_size!(WanTrieTbl, skel::wan_trie_tbl);
        assert_field!(WanTrieHalf, skel::wan_trie_half, node_cnt);
        assert_field!(WanTrieHalf, skel::wan_trie_half, nodes);
        assert_field!(WanTrieHalf, skel::wan_trie_half, vals);
        assert_field!(WanTrieTbl, skel::wan_trie_tbl, cur);
        assert_field!(WanTrieTbl, skel::wan_trie_tbl, halves);
    }
}
