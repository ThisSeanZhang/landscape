use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::tests::xdp_wan_route_skel::XdpWanRouteSkelBuilder;
use crate::tests::PinRootGuard;

fn test_pin_root() -> PinRootGuard {
    PinRootGuard::new("xdp-wr")
}

#[test]
fn xdp_wan_route_verifier_smoke() {
    let mut builder = XdpWanRouteSkelBuilder::default();
    let pin_root = test_pin_root();
    {
        let obj_builder = builder.object_builder_mut();
        obj_builder.debug(true);
        obj_builder.pin_root_path(&pin_root).unwrap();
    }

    let mut obj = MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let _skel = open.load().expect("verifier rejected the program");
}

#[test]
#[ignore = "requires specific BPF map / kernel environment"]
fn xdp_wan_route_testrun_pass() {
    let mut builder = XdpWanRouteSkelBuilder::default();
    let pin_root = test_pin_root();
    builder.object_builder_mut().pin_root_path(&pin_root).unwrap();

    let mut obj = MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let skel = open.load().expect("load skel");

    let pkt = super::dummpy_tcp_pkg();
    let result = skel
        .progs
        .xdp_wan_route_ingress
        .test_run(ProgramInput { data_in: Some(&pkt), ..Default::default() })
        .expect("test_run");

    assert!(
        result.return_value == 2 || result.return_value == 4,
        "expected XDP_PASS (2) or XDP_REDIRECT (4), got {}",
        result.return_value
    );
}
