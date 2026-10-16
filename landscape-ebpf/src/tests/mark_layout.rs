//! Echo test: pin the "Rust encodes / eBPF decodes" mark layout contract.
//!
//! Rust builds `SocketMark` values via landscape-common (the single Rust-side
//! encode path) and feeds them through PROG_TEST_RUN into the test-only BPF
//! program `test_mark_type_decode` (src/bpf/tests/base/test_mark_type.bpf.c),
//! which decodes with the C helpers in `bpf/base/mark.h`
//! (`get_mark_type` / `get_host_direct_chain_id`).
//!
//! The wire format itself is pinned by hand-written hex oracle tests in
//! `landscape-common`'s mark.rs; this module closes the cross-language half.

use std::net::Ipv4Addr;
use std::str::FromStr;

use landscape_common::flow::mark::{FlowMark, FlowMarkAction, MarkType, SocketMark};
use libbpf_rs::{
    ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};
use zerocopy::IntoBytes;

use crate::tests::{TestSkb, isolated_pin_root, route::packet_builder::simple_ipv4_tcp};

pub(crate) mod test_mark_type {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_mark_type.skel.rs"));
}

/// Feed `mark` through the echo program, return `(chain_id, mark_type)`.
fn run_decode(mark: u32) -> (u32, u32) {
    let pin_root = isolated_pin_root("mark-layout");
    let mut builder = test_mark_type::TestMarkTypeSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut open_object = std::mem::MaybeUninit::uninit();
    let skel = builder.open(&mut open_object).unwrap().load().unwrap();

    let pkt = simple_ipv4_tcp(
        Ipv4Addr::from_str("192.168.1.10").unwrap(),
        Ipv4Addr::from_str("10.0.0.20").unwrap(),
    );
    let mut ctx = TestSkb { mark, ..Default::default() };
    let mut out = vec![0_u8; pkt.len()];
    let mut ctx_out = TestSkb::default();
    skel.progs
        .test_mark_type_decode
        .test_run(ProgramInput {
            data_in: Some(&pkt),
            data_out: Some(&mut out),
            context_in: Some(ctx.as_mut_bytes()),
            context_out: Some(ctx_out.as_mut_bytes()),
            ..Default::default()
        })
        .expect("run test_mark_type_decode");
    (ctx_out.cb[0], ctx_out.cb[1])
}

#[test]
fn mark_type_echo_host_direct() {
    // trace bits (16-23) ride along and must not disturb the C decode.
    let sm = SocketMark::new(MarkType::HostDirect { chain_id: 0x1234 }, 0x56);
    let (chain_id, mark_type) = run_decode(u32::from(sm));
    assert_eq!(mark_type, 1, "C must read MARK_TYPE_HOST_DIRECT");
    assert_eq!(chain_id, 0x1234, "C must read the chain id from bits 0-15");
}

#[test]
fn mark_type_echo_normal() {
    let sm =
        SocketMark::new(MarkType::Normal(FlowMark::new(FlowMarkAction::Redirect, 5, false)), 0);
    let (low_bits, mark_type) = run_decode(u32::from(sm));
    assert_eq!(mark_type, 0, "C must read MARK_TYPE_NORMAL");
    // the bits 0-15 helper is layout-agnostic: it mirrors the FlowMark payload
    assert_eq!(low_bits, 0x0305);
}
