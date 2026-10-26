//! Test facade: tiered module declarations plus single-inclusion points for
//! test-only BPF skeletons.
//!
//! Layout (directory == feature tier):
//!
//! - [`helper`]: shared infrastructure, compiled under bare `test-support`
//!   (packet/frame builders, map seeding, netns utils, wire mirror types).
//! - [`stage`]: runtime-stage behaviour tests (production skeletons only).
//! - [`route`] / [`nat`] / [`chain`] / [`metric`] / [`misc`]:
//!   topic suites, each pulling its own test-only BPF objects.
#![cfg_attr(not(feature = "bpf-test"), allow(dead_code, unused_imports))]

pub(crate) mod helper;
pub(crate) mod pkt;

// Curated re-exports so consumers can keep `crate::tests::<item>` paths.
pub(crate) use helper::skb::TestSkb;
pub(crate) use helper::{check_ifindex, init_shared_maps_for_test, isolated_pin_root, test_id};

#[cfg(feature = "test-chain")]
mod chain;
#[cfg(feature = "test-metric")]
mod metric;
#[cfg(feature = "test-misc")]
mod misc;
#[cfg(feature = "test-nat")]
mod nat;
#[cfg(feature = "test-reader")]
mod reader;
#[cfg(feature = "test-route")]
pub(crate) mod route;
mod stage;

// Test-only skeleton single-inclusion points. Each gate is the union of its
// consumers' feature gates; the BPF sources live under src/bpf/tests/<topic>/.
#[cfg(feature = "test-route")]
pub(crate) mod test_route_packet {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_route_packet.skel.rs"));
}

#[cfg(feature = "test-misc")]
pub(crate) mod test_tproxy_packet {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_tproxy_packet.skel.rs"));
}

#[cfg(feature = "test-chain")]
pub(crate) mod test_xdp_root {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_root.skel.rs"));
}

#[cfg(feature = "test-chain")]
pub(crate) mod test_xdp_chain_stage {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_chain_stage.skel.rs"));
}

// chain tests and the NAT session tests share this helper program.
#[cfg(any(feature = "test-chain", feature = "test-nat"))]
pub(crate) mod test_xdp_dummy {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_dummy.skel.rs"));
}

#[cfg(feature = "test-reader")]
pub(crate) mod test_tc_read_head4_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_tc_read_head4.skel.rs"));
}

#[cfg(feature = "test-reader")]
pub(crate) mod test_tc_read_head6_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_tc_read_head6.skel.rs"));
}

#[cfg(feature = "test-nat")]
pub(crate) mod test_xdp_nat4_modify_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_nat4_modify.skel.rs"));
}

#[cfg(feature = "test-nat")]
pub(crate) mod tc_nat4_v4_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_nat4_v4.skel.rs"));
}

#[cfg(feature = "test-misc")]
pub(crate) mod test_csum_verify_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_csum_verify.skel.rs"));
}

#[cfg(feature = "test-misc")]
pub(crate) mod test_wan_trie_probe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_wan_trie_probe.skel.rs"));
}
