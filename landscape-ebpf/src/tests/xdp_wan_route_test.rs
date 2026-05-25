use std::mem::MaybeUninit;
use std::path::PathBuf;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    ProgramInput,
};

use crate::tests::xdp_wan_route_skel::XdpWanRouteSkelBuilder;

fn test_pin_root() -> PathBuf {
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/xdp-wr-{}-{}",
        std::process::id(),
        crate::tests::test_id()
    ));
    let _ = std::fs::create_dir_all(&path);
    path
}

#[test]
fn xdp_wan_route_verifier_smoke() {
    let mut builder = XdpWanRouteSkelBuilder::default();
    {
        let obj_builder = builder.object_builder_mut();
        obj_builder.debug(true);
        obj_builder.pin_root_path(&test_pin_root()).unwrap();
    }

    let mut obj = MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let _skel = open.load().expect("verifier rejected the program");
}

#[test]
fn xdp_wan_route_testrun_pass() {
    let mut builder = XdpWanRouteSkelBuilder::default();
    builder.object_builder_mut().pin_root_path(&test_pin_root()).unwrap();

    let mut obj = MaybeUninit::uninit();
    let open = builder.open(&mut obj).expect("open skel");
    let skel = open.load().expect("load skel");

    let mut pkt = super::dummpy_tcp_pkg();
    let result = skel
        .progs
        .xdp_wan_route_ingress
        .test_run(ProgramInput { data_in: Some(&mut pkt), ..Default::default() })
        .expect("test_run");

    assert!(
        result.return_value == 2 || result.return_value == 4,
        "expected XDP_PASS (2) or XDP_REDIRECT (4), got {}",
        result.return_value
    );
}
