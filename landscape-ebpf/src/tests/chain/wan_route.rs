use std::mem::MaybeUninit;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};

use crate::tests::net_utils::{
    build_tcp_pkt, dummy_recv_count, dummy_reset, send_raw_packet, wait_for, NetNsGuard, VethPair,
};
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;
use crate::tests::xdp_wan_route_skel::XdpWanRouteSkelBuilder;

#[test]
fn xdp_wan_route_verifier_smoke() {
    let mut builder = XdpWanRouteSkelBuilder::default();
    let pin_root = crate::tests::isolated_pin_root("wr");
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
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn xdp_wan_route_ingress_redirect() {
    let test_ns = NetNsGuard::create("wr1");
    let peer_ns = NetNsGuard::create("wr1p");
    let pair;
    let out_pair;
    {
        let _e = test_ns.enter();
        pair = VethPair::create_with_netns("wr1", &peer_ns);
        // redirect target must be a device other than the ingress (the program
        // passes when lan_info->ifindex == ingress), so use a second pair kept
        // in the test netns.
        out_pair = VethPair::create("wr1out");
    }
    let peer = pair.peer();
    let h_i;
    let out_h_i;
    {
        let _e = test_ns.enter();
        h_i = pair.host_ifindex();
        out_h_i = out_pair.host_ifindex();
    }

    let pin_root = crate::tests::isolated_pin_root("xdp-wr-redir");
    let mut b = XdpWanRouteSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();

    // lan route → out-pair host veth (same netns as the program), no MAC required
    let mut lan_key = [0u8; 8];
    lan_key[0..4].copy_from_slice(&32u32.to_ne_bytes());
    lan_key[4..8].copy_from_slice(&0x0A000005u32.to_be_bytes());
    let mut lan_val = [0u8; 16];
    lan_val[8..12].copy_from_slice(&out_h_i.to_ne_bytes());
    skel.maps.rt4_lan_map.update(&lan_key, &lan_val, MapFlags::ANY).unwrap();

    // allow XDP redirect to the out-pair host veth
    skel.maps
        .xdp_redirect_able
        .update(&out_h_i.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // counting dummy on the out-pair peer (where redirected packets land)
    let mut db = TestXdpDummySkelBuilder::default();
    db.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut dobj = MaybeUninit::uninit();
    let dummy = db.open(&mut dobj).unwrap().load().unwrap();

    let _link;
    let _dl;
    {
        let _e = test_ns.enter();
        _link = skel.progs.xdp_wan_route_ingress.attach_xdp(h_i as i32).unwrap();
        _dl = dummy.progs.xdp_test_dummy.attach_xdp(out_pair.peer_ifindex() as i32).unwrap();
    }

    let pkt = build_tcp_pkt([10, 0, 0, 1], [10, 0, 0, 5]);
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = peer_ns.enter();
        send_raw_packet(peer, &pkt);
    }
    wait_for("wan_route redirected packet to LAN peer", std::time::Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    drop(dummy);
    drop(skel);
}
