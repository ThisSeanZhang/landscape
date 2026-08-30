// ── TC chain: two-netns integration tests ──
//
// Attach the TC classifier programs to a real veth and observe redirected /
// encapsulated frames landing on the peer side (real skb, real meta handoff).

use std::mem::MaybeUninit;
use std::process::Command;
use std::time::Duration;

use etherparse::{IcmpEchoHeader, Icmpv4Type, PacketBuilder};
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};

use crate::tests::net_utils::{
    build_tcp_pkt, dummy_recv_count, dummy_recv_other, dummy_reset, send_raw_packet, settle,
    wait_for, NetNsGuard, TCAttach, VethPair,
};
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;
use crate::tests::xdp_lan_intro_skel::XdpLanIntroSkelBuilder;

pub(crate) mod tc_lan_ingress_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_lan_ingress_intro.skel.rs"));
}
use tc_lan_ingress_intro_skel::TcLanIngressIntroSkelBuilder;

pub(crate) mod tc_pppoe_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/tc_pppoe.skel.rs"));
}
use tc_pppoe_skel::types::pppoe_egress_tmpl;
use tc_pppoe_skel::TcPppoeSkelBuilder;

/// Common two-veth-pair environment: an ingress pair crossing into a peer
/// netns, plus an out pair kept entirely in the test netns (redirect target).
struct TcEnv {
    test_ns: NetNsGuard,
    peer_ns: NetNsGuard,
    pair: VethPair,
    out_pair: VethPair,
    h_i: u32,
    out_h_i: u32,
}

impl TcEnv {
    fn two_pairs(prefix: &str) -> Self {
        let test_ns = NetNsGuard::create(prefix);
        let peer_ns = NetNsGuard::create(&format!("{prefix}p"));
        let (pair, out_pair) = {
            let _e = test_ns.enter();
            (VethPair::create_with_netns(prefix, &peer_ns), VethPair::create(&format!("{prefix}o")))
        };
        let (h_i, out_h_i) = {
            let _e = test_ns.enter();
            (pair.host_ifindex(), out_pair.host_ifindex())
        };
        TcEnv { test_ns, peer_ns, pair, out_pair, h_i, out_h_i }
    }
}

fn icmp_echo(src_mac: [u8; 6], dst_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(src_mac, dst_mac)
        .ipv4(src_ip, dst_ip, 64)
        .icmpv4(Icmpv4Type::EchoRequest(IcmpEchoHeader { id: 1, seq: 1 }));
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build icmp packet");
    pkt
}

fn pppoe_tmpl(session_id: u16) -> pppoe_egress_tmpl {
    pppoe_egress_tmpl {
        dmac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
        smac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
        eth_proto: 0x8864u16.to_be(),
        ver_type: 0x11,
        code: 0x00,
        session_id: session_id.to_be(),
        ..Default::default()
    }
}

fn lan_key_v4(dst: [u8; 4]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0..4].copy_from_slice(&32u32.to_ne_bytes());
    k[4..8].copy_from_slice(&dst);
    k
}

// ── 1: tc_lan_ingress_intro on a real veth redirects to the out pair ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn tc_lan_ingress_redirect() {
    let env = TcEnv::two_pairs("tclin");
    let pin_root = crate::tests::isolated_pin_root("tc-lan-redir");

    let mut b = TcLanIngressIntroSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();

    // LAN route → out-pair host veth (must differ from the ingress device)
    let mut lan_val = [0u8; 16];
    lan_val[8..12].copy_from_slice(&env.out_h_i.to_ne_bytes());
    skel.maps.rt4_lan_map.update(&lan_key_v4([10, 0, 0, 5]), &lan_val, MapFlags::ANY).unwrap();

    // counting dummy on the out-pair peer
    let mut db = TestXdpDummySkelBuilder::default();
    db.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut dobj = MaybeUninit::uninit();
    let dummy = db.open(&mut dobj).unwrap().load().unwrap();

    let _attach;
    let _dl;
    {
        let _e = env.test_ns.enter();
        _attach = TCAttach::attach_ingress(&skel.progs.tc_lan_ingress_intro, env.h_i as i32);
        _dl = dummy.progs.xdp_test_dummy.attach_xdp(env.out_pair.peer_ifindex() as i32).unwrap();
    }

    let pkt = build_tcp_pkt([10, 0, 0, 1], [10, 0, 0, 5]);
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = env.peer_ns.enter();
        send_raw_packet(env.pair.peer(), &pkt);
    }
    wait_for("TC LAN redirect delivered to out peer", Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    // the sender MAC/IP was learned (learn_src_ip_mac_v4_tc)
    let mut mac_key = [0u8; 4];
    mac_key.copy_from_slice(&[10, 0, 0, 1]);
    let learned = skel.maps.ip_mac_v4.lookup(&mac_key, MapFlags::ANY).unwrap();
    let raw = learned.expect("ip_mac_v4 should have learned the sender 10.0.0.1");
    assert_eq!(&raw[4..10], &[0x02, 0, 0, 0, 0, 0x01], "learned sender MAC");

    drop(dummy);
    drop(skel);
}

// ── 2: XDP→TC meta handoff bridge (XDP writes meta, TC redirects) ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn tc_handoff_bridge() {
    let env = TcEnv::two_pairs("tchof");
    let pin_root = crate::tests::isolated_pin_root("tc-handoff");

    // XDP lan_intro pins the shared maps first; the TC program reuses them.
    let mut xb = XdpLanIntroSkelBuilder::default();
    xb.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut xobj = MaybeUninit::uninit();
    let xskel = xb.open(&mut xobj).unwrap().load().unwrap();

    let mut tb = TcLanIngressIntroSkelBuilder::default();
    tb.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut tobj = MaybeUninit::uninit();
    let mut topen = tb.open(&mut tobj).unwrap();
    topen.maps.rodata_data.as_deref_mut().unwrap().xdp_handoff_enabled = true;
    let tskel = topen.load().unwrap();

    // LAN route → out-pair host veth; xdp_redirect_able stays EMPTY so the
    // XDP program takes the TC-handoff path (writes XDP_HANDOFF_TC_REDIRECT_MAGIC).
    let mut lan_val = [0u8; 16];
    lan_val[8..12].copy_from_slice(&env.out_h_i.to_ne_bytes());
    xskel.maps.rt4_lan_map.update(&lan_key_v4([10, 0, 0, 5]), &lan_val, MapFlags::ANY).unwrap();

    // counting dummy on the out-pair peer
    let mut db = TestXdpDummySkelBuilder::default();
    db.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut dobj = MaybeUninit::uninit();
    let dummy = db.open(&mut dobj).unwrap().load().unwrap();

    let _xl;
    let _attach;
    let _dl;
    {
        let _e = env.test_ns.enter();
        _xl = xskel.progs.xdp_lan_intro.attach_xdp(env.h_i as i32).unwrap();
        _attach = TCAttach::attach_ingress(&tskel.progs.tc_lan_ingress_intro, env.h_i as i32);
        _dl = dummy.progs.xdp_test_dummy.attach_xdp(env.out_pair.peer_ifindex() as i32).unwrap();
    }

    let pkt = build_tcp_pkt([10, 0, 0, 1], [10, 0, 0, 5]);
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = env.peer_ns.enter();
        send_raw_packet(env.pair.peer(), &pkt);
    }
    wait_for("XDP→TC handoff meta redirected to out peer", Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    drop(dummy);
    drop(xskel);
    drop(tskel);
}

// ── 3: tc_firewall WAN egress/ingress on a real veth ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn tc_firewall_wan_egress_ingress() {
    let env = TcEnv::two_pairs("tcfw");
    {
        let _e = env.test_ns.enter();
        Command::new("ip")
            .args(["link", "set", "dev", env.pair.host(), "address", "02:00:00:00:00:01"])
            .output()
            .unwrap();
        Command::new("ip")
            .args(["addr", "add", "10.0.0.1/24", "dev", env.pair.host()])
            .output()
            .unwrap();
        // the veth XDP-pass path strips the Ethernet header before the stack,
        // so the kernel cannot learn the sender MAC from the ping; seed the
        // neighbour entry so the ICMP reply goes out immediately.
        Command::new("ip")
            .args([
                "neigh",
                "replace",
                "10.0.0.2",
                "lladdr",
                "02:00:00:00:00:02",
                "dev",
                env.pair.host(),
            ])
            .output()
            .unwrap();
    }

    let pin_root = crate::tests::isolated_pin_root("tc-fw");
    let mut b = crate::stages::firewall::tc_firewall_skel::TcFirewallSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = MaybeUninit::uninit();
    let skel = b.open(&mut obj).unwrap().load().unwrap();

    let mut db = TestXdpDummySkelBuilder::default();
    db.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut dobj = MaybeUninit::uninit();
    let dummy = db.open(&mut dobj).unwrap().load().unwrap();

    let _ae;
    let _ai;
    let _dl;
    {
        let _e = env.test_ns.enter();
        _ae = TCAttach::attach_egress(&skel.progs.tc_firewall_wan_egress, env.h_i as i32);
        _ai = TCAttach::attach_ingress(&skel.progs.tc_firewall_wan_ingress, env.h_i as i32);
    }
    {
        let _e = env.peer_ns.enter();
        _dl = dummy.progs.xdp_test_dummy.attach_xdp(env.pair.peer_ifindex() as i32).unwrap();
    }

    // block map key: ipv4_lpm_key { prefixlen = 32, addr }
    let block_key = || {
        let mut k = [0u8; 8];
        k[0..4].copy_from_slice(&32u32.to_ne_bytes());
        k
    };
    let block_val = [1u8, 0, 0, 0];

    // 1) egress allow: outbound frame reaches the peer
    let out =
        icmp_echo([0x02, 0, 0, 0, 0, 0x02], [0x02, 0, 0, 0, 0, 0x05], [10, 0, 0, 2], [10, 0, 0, 5]);
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = env.test_ns.enter();
        send_raw_packet(env.pair.host(), &out);
    }
    wait_for("egress firewall passed frame to peer", Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    // 2) egress block (daddr) → frame dropped
    let mut k = block_key();
    k[4..8].copy_from_slice(&[10, 0, 0, 5]);
    skel.maps.firewall_block_ip4_map.update(&k, &block_val, MapFlags::ANY).unwrap();
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = env.test_ns.enter();
        send_raw_packet(env.pair.host(), &out);
    }
    settle(300);
    assert_eq!(
        dummy_recv_count(&dummy.maps.dummy_recv_map, false),
        0,
        "egress firewall should drop the blocked daddr"
    );
    skel.maps.firewall_block_ip4_map.delete(&k).unwrap();

    // 3) ingress allow: peer pings the host veth IP, reply comes back
    let ping =
        icmp_echo([0x02, 0, 0, 0, 0, 0x02], [0x02, 0, 0, 0, 0, 0x01], [10, 0, 0, 2], [10, 0, 0, 1]);
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = env.peer_ns.enter();
        send_raw_packet(env.pair.peer(), &ping);
    }
    wait_for("ingress firewall passed ping, host replied", Duration::from_secs(5), || {
        dummy_recv_count(&dummy.maps.dummy_recv_map, false) == 1
    });

    // 4) ingress block (saddr) → no reply
    let mut k = block_key();
    k[4..8].copy_from_slice(&[10, 0, 0, 2]);
    skel.maps.firewall_block_ip4_map.update(&k, &block_val, MapFlags::ANY).unwrap();
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = env.peer_ns.enter();
        send_raw_packet(env.pair.peer(), &ping);
    }
    settle(300);
    assert_eq!(
        dummy_recv_count(&dummy.maps.dummy_recv_map, false),
        0,
        "ingress firewall should drop the blocked saddr"
    );

    drop(dummy);
    drop(skel);
}

// ── 4: tc_pppoe_wan_egress encapsulation on a real veth ──

#[test]
#[ignore = "requires root and veth pairs; run with --include-ignored"]
fn tc_pppoe_wan_egress_encap() {
    let env = TcEnv::two_pairs("tcppp");
    {
        let _e = env.test_ns.enter();
        Command::new("ip")
            .args(["addr", "add", "10.0.0.1/24", "dev", env.pair.host()])
            .output()
            .unwrap();
        Command::new("ip")
            .args([
                "neigh",
                "replace",
                "10.0.0.2",
                "lladdr",
                "02:00:00:00:00:02",
                "dev",
                env.pair.host(),
            ])
            .output()
            .unwrap();
    }
    let pin_root = crate::tests::isolated_pin_root("tc-pppoe");

    let mut b = TcPppoeSkelBuilder::default();
    b.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut obj = MaybeUninit::uninit();
    let mut open = b.open(&mut obj).unwrap();
    open.maps.rodata_data.as_deref_mut().unwrap().pppoe_tmpl = pppoe_tmpl(0x2233);
    let skel = open.load().unwrap();

    let mut db = TestXdpDummySkelBuilder::default();
    db.object_builder_mut().pin_root_path(&pin_root).unwrap();
    let mut dobj = MaybeUninit::uninit();
    let dummy = db.open(&mut dobj).unwrap().load().unwrap();

    let _attach;
    let _dl;
    {
        let _e = env.test_ns.enter();
        _attach = TCAttach::attach_egress(&skel.progs.tc_pppoe_wan_egress, env.h_i as i32);
    }
    {
        let _e = env.peer_ns.enter();
        _dl = dummy.progs.xdp_test_dummy.attach_xdp(env.pair.peer_ifindex() as i32).unwrap();
    }

    // ICMP echo from the host stack exits the host veth → egress encapsulation
    // → the peer receives a PPPoE frame (counted as "other", not v4)
    dummy_reset(&dummy.maps.dummy_recv_map);
    {
        let _e = env.test_ns.enter();
        let _ = Command::new("ping").args(["-c", "1", "-W", "1", "10.0.0.2"]).output().unwrap();
    }
    wait_for("egress PPPoE encapsulated frame reached peer", Duration::from_secs(5), || {
        dummy_recv_other(&dummy.maps.dummy_recv_map) >= 1
    });
    assert_eq!(
        dummy_recv_count(&dummy.maps.dummy_recv_map, false),
        0,
        "encapsulated frame must not be counted as plain IPv4"
    );

    drop(dummy);
    drop(skel);
}
