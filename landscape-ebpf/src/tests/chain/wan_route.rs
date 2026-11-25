use std::mem::MaybeUninit;
use std::net::Ipv6Addr;
use std::str::FromStr;

use libbpf_rs::{
    MapCore, MapFlags, ProgramInput,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::skel::xdp_wan_route::XdpWanRouteSkelBuilder;
use crate::tests::helper::map::{
    LAN_ROUTE_TYPE, TARGET_IFINDEX, WAN_IFINDEX, WAN_ROUTE_TYPE, insert_route6_lan_entry,
};
use crate::tests::helper::net::{
    NetNsGuard, VethPair, build_tcp_pkt, dummy_recv_count, dummy_reset, send_raw_packet, wait_for,
};
use crate::tests::pkt::simple_ipv6_tcp_syn;
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;

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

#[test]
fn xdp_wan_route_v6_pd_wan_host_128_coexists_with_covering_lan_prefix() {
    // Regression: XDP WAN ingress with a covering LAN /64 and a WAN /128 host
    // route (WanReachable) under the same prefix must pass the /128 to the
    // local stack (XDP_PASS) without relying on wan_ip_binding, while another
    // address in the same /64 still redirects to LAN (XDP_REDIRECT).
    const XDP_PASS: u32 = 2;
    const XDP_REDIRECT: u32 = 4;

    let pin_root = crate::tests::isolated_pin_root("xdp-wr-pd128-coexist");
    let mut b = XdpWanRouteSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();

    let public_src = Ipv6Addr::from_str("2001:db8:1::7").unwrap();
    let pd_prefix = Ipv6Addr::from_str("2001:db8:42::").unwrap();
    let pd_lan_gw = Ipv6Addr::from_str("2001:db8:42::1").unwrap();
    let wan_pd_host = Ipv6Addr::from_str("2001:db8:42::10").unwrap();
    let lan_peer = Ipv6Addr::from_str("2001:db8:42::20").unwrap();

    // Covering LAN prefix (/64) -> TARGET_IFINDEX (marked XDP redirect-able).
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        64,
        pd_prefix,
        pd_lan_gw,
        LAN_ROUTE_TYPE,
        TARGET_IFINDEX,
        false,
        [0; 6],
    );
    skel.maps
        .xdp_redirect_able
        .update(&TARGET_IFINDEX.to_ne_bytes(), &1u32.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    // WAN /128 host route (WanReachable) under the same /64.
    // wan_ip_binding is intentionally omitted so xdp_route6_is_current_wan_packet
    // cannot short-circuit before rt6_lan_map lookup.
    insert_route6_lan_entry(
        &skel.maps.rt6_lan_map,
        128,
        wan_pd_host,
        wan_pd_host,
        WAN_ROUTE_TYPE,
        WAN_IFINDEX,
        false,
        [0; 6],
    );

    let host_pkt = simple_ipv6_tcp_syn(public_src, wan_pd_host);
    let mut host_out = vec![0u8; host_pkt.len().max(64) + 32];
    let host_res = skel
        .progs
        .xdp_wan_route_ingress
        .test_run(ProgramInput {
            data_in: Some(&host_pkt),
            data_out: Some(&mut host_out),
            ..Default::default()
        })
        .expect("run xdp_wan_route_ingress for WAN /128");
    assert_eq!(
        host_res.return_value, XDP_PASS,
        "WAN /128 under covering LAN /64 must pass to local stack"
    );
    assert_eq!(host_res.data.expect("data_out"), host_pkt.as_slice());

    let lan_pkt = simple_ipv6_tcp_syn(public_src, lan_peer);
    let mut lan_out = vec![0u8; lan_pkt.len().max(64) + 32];
    let lan_res = skel
        .progs
        .xdp_wan_route_ingress
        .test_run(ProgramInput {
            data_in: Some(&lan_pkt),
            data_out: Some(&mut lan_out),
            ..Default::default()
        })
        .expect("run xdp_wan_route_ingress for LAN peer");
    assert_eq!(
        lan_res.return_value, XDP_REDIRECT,
        "other LAN address in same /64 must still redirect to LAN"
    );
}
