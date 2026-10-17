//! Single inclusion point for every runtime BPF skeleton.
//!
//! Each `#[path]` module loads one generated `src/bpf_rs/{name}.skel.rs`
//! exactly once (mirroring `cargo libbpf gen`'s module layout), so the
//! embedded object bytes and skeleton types are compiled a single time
//! instead of once per consumer. Reference types via
//! `crate::skel::{name}::{Skel, SkelBuilder, types, ...}`.
//!
//! Test- and bench-only skeletons (`test_*`, `bench_*`) are intentionally
//! NOT listed here: they stay feature-gated and are included on-site in
//! `crate::tests` / `crate::bench`.

#[path = "../bpf_rs/neigh_update.skel.rs"]
pub mod neigh_update;
#[path = "../bpf_rs/pppoe_client.skel.rs"]
pub mod pppoe_client;
#[path = "../bpf_rs/pppoe_skb_fallback.skel.rs"]
pub mod pppoe_skb_fallback;
#[path = "../bpf_rs/sk_dns_dispatcher.skel.rs"]
pub mod sk_dns_dispatcher;
#[path = "../bpf_rs/tc_firewall.skel.rs"]
pub mod tc_firewall;
#[path = "../bpf_rs/tc_lan_dao.skel.rs"]
pub mod tc_lan_dao;
#[path = "../bpf_rs/tc_lan_ingress_route.skel.rs"]
pub mod tc_lan_ingress_route;
#[path = "../bpf_rs/tc_mss.skel.rs"]
pub mod tc_mss;
#[path = "../bpf_rs/tc_nat4.skel.rs"]
pub mod tc_nat4;
#[path = "../bpf_rs/tc_nat6.skel.rs"]
pub mod tc_nat6;
#[path = "../bpf_rs/tc_pppoe.skel.rs"]
pub mod tc_pppoe;
#[path = "../bpf_rs/tc_wan_egress_exit.skel.rs"]
pub mod tc_wan_egress_exit;
#[path = "../bpf_rs/tc_wan_egress_root.skel.rs"]
pub mod tc_wan_egress_root;
#[path = "../bpf_rs/tc_wan_egress_route.skel.rs"]
pub mod tc_wan_egress_route;
#[path = "../bpf_rs/tc_wan_ingress_intro.skel.rs"]
pub mod tc_wan_ingress_intro;
#[path = "../bpf_rs/tc_wan_ingress_root.skel.rs"]
pub mod tc_wan_ingress_root;
#[path = "../bpf_rs/tc_wan_ingress_route.skel.rs"]
pub mod tc_wan_ingress_route;
#[path = "../bpf_rs/tproxy.skel.rs"]
pub mod tproxy;
#[path = "../bpf_rs/xdp_firewall.skel.rs"]
pub mod xdp_firewall;
#[path = "../bpf_rs/xdp_lan_exit.skel.rs"]
pub mod xdp_lan_exit;
#[path = "../bpf_rs/xdp_lan_root.skel.rs"]
pub mod xdp_lan_root;
#[path = "../bpf_rs/xdp_lan_route.skel.rs"]
pub mod xdp_lan_route;
#[path = "../bpf_rs/xdp_mss.skel.rs"]
pub mod xdp_mss;
#[path = "../bpf_rs/xdp_nat4.skel.rs"]
pub mod xdp_nat4;
#[path = "../bpf_rs/xdp_nat6.skel.rs"]
pub mod xdp_nat6;
#[path = "../bpf_rs/xdp_pppoe.skel.rs"]
pub mod xdp_pppoe;
#[path = "../bpf_rs/xdp_wan_intro.skel.rs"]
pub mod xdp_wan_intro;
#[path = "../bpf_rs/xdp_wan_root.skel.rs"]
pub mod xdp_wan_root;
#[path = "../bpf_rs/xdp_wan_route.skel.rs"]
pub mod xdp_wan_route;
