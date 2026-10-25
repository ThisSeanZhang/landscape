use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::time::Duration;

use libbpf_rs::{
    MapCore, MapFlags,
    skel::{OpenSkel, SkelBuilder as _},
};

use crate::skel::xdp_firewall::XdpFirewallSkelBuilder;
use crate::skel::xdp_nat4_v4::{XdpNat4V4Skel, XdpNat4V4SkelBuilder, types};
use crate::skel::xdp_nat6::XdpNat6SkelBuilder;
use crate::tests::helper::net::{VethPair, send_raw_packet, settle, wait_for};
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;

const WAN_IP: [u8; 4] = [203, 0, 113, 1];
const LAN_IP: [u8; 4] = [192, 168, 1, 100];
const REMOTE_IP: [u8; 4] = [10, 0, 0, 1];

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

const KIND_DYNAMIC: u8 = 1;
const KIND_STATIC: u8 = 2;
const STATE_ACTIVE: u64 = 1;
const STATE_SHIFT: u64 = 56;
const CT_ACTIVE: u64 = 20;

const NAPT_FROM_WAN_TCP_BASE: u32 = 65536;
const NAPT_FROM_WAN_ICMP_BASE: u32 = 131072;

fn as_bytes<T>(value: &T) -> &[u8] {
    unsafe {
        std::slice::from_raw_parts((value as *const T).cast::<u8>(), std::mem::size_of::<T>())
    }
}

fn be32(addr: [u8; 4]) -> u32 {
    u32::from_ne_bytes(addr)
}

fn state_ref(state: u64, refs: u64) -> u64 {
    (state << STATE_SHIFT) | refs
}

fn lan_key(addr: [u8; 4], port: u16, proto: u8) -> types::napt_from_lan_key {
    types::napt_from_lan_key {
        internal_addr: be32(addr),
        internal_port: port.to_be(),
        proto,
        pad: 0,
    }
}

fn wan_index(proto: u8, port: u16) -> u32 {
    let base = match proto {
        PROTO_UDP => 0,
        PROTO_TCP => NAPT_FROM_WAN_TCP_BASE,
        PROTO_ICMP => NAPT_FROM_WAN_ICMP_BASE,
        _ => panic!("bad proto"),
    };
    base + u32::from(port)
}

fn ct_key(
    internal_addr: [u8; 4],
    internal_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
    proto: u8,
) -> types::napt_ct_key {
    types::napt_ct_key {
        internal_addr: be32(internal_addr),
        remote_addr: be32(remote_addr),
        internal_port: internal_port.to_be(),
        remote_port: remote_port.to_be(),
        proto,
        pad: [0; 3],
    }
}

fn seed_static(
    nat: &XdpNat4V4Skel<'_>,
    proto: u8,
    internal_addr: [u8; 4],
    internal_port: u16,
    external_port: u16,
) {
    let lan = types::napt_from_lan_value {
        external_port: external_port.to_be(),
        kind: KIND_STATIC,
        allow_reuse: 1,
        generation: 0,
        trigger_addr: 0,
        trigger_port: 0,
        pad: 0,
    };
    nat.maps
        .napt_from_lan
        .update(
            as_bytes(&lan_key(internal_addr, internal_port, proto)),
            as_bytes(&lan),
            MapFlags::ANY,
        )
        .unwrap();

    let wan = types::napt_from_wan_value {
        internal_addr: be32(internal_addr),
        internal_port: internal_port.to_be(),
        kind: KIND_STATIC,
        allow_reuse: 1,
        trigger_addr: 0,
        trigger_port: 0,
        pad0: 0,
        generation: 0,
        pad1: 0,
        state_ref: state_ref(STATE_ACTIVE, 0),
    };
    nat.maps
        .napt_from_wan
        .update(&wan_index(proto, external_port).to_ne_bytes(), as_bytes(&wan), MapFlags::ANY)
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn seed_dynamic(
    nat: &XdpNat4V4Skel<'_>,
    proto: u8,
    internal_addr: [u8; 4],
    internal_port: u16,
    external_port: u16,
    trigger_addr: [u8; 4],
    trigger_port: u16,
    generation: u32,
    refs: u64,
    allow_reuse: u8,
) {
    let lan = types::napt_from_lan_value {
        external_port: external_port.to_be(),
        kind: KIND_DYNAMIC,
        allow_reuse,
        generation,
        trigger_addr: be32(trigger_addr),
        trigger_port: trigger_port.to_be(),
        pad: 0,
    };
    nat.maps
        .napt_from_lan
        .update(
            as_bytes(&lan_key(internal_addr, internal_port, proto)),
            as_bytes(&lan),
            MapFlags::ANY,
        )
        .unwrap();

    let wan = types::napt_from_wan_value {
        internal_addr: be32(internal_addr),
        internal_port: internal_port.to_be(),
        kind: KIND_DYNAMIC,
        allow_reuse,
        trigger_addr: be32(trigger_addr),
        trigger_port: trigger_port.to_be(),
        pad0: 0,
        generation,
        pad1: 0,
        state_ref: state_ref(STATE_ACTIVE, refs),
    };
    nat.maps
        .napt_from_wan
        .update(&wan_index(proto, external_port).to_ne_bytes(), as_bytes(&wan), MapFlags::ANY)
        .unwrap();
}

fn lookup_lan(
    nat: &XdpNat4V4Skel<'_>,
    internal_addr: [u8; 4],
    internal_port: u16,
    proto: u8,
) -> Option<types::napt_from_lan_value> {
    let bytes = nat
        .maps
        .napt_from_lan
        .lookup(as_bytes(&lan_key(internal_addr, internal_port, proto)), MapFlags::ANY)
        .unwrap()?;
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
}

fn lookup_wan(
    nat: &XdpNat4V4Skel<'_>,
    proto: u8,
    external_port: u16,
) -> Option<types::napt_from_wan_value> {
    let bytes = nat
        .maps
        .napt_from_wan
        .lookup(&wan_index(proto, external_port).to_ne_bytes(), MapFlags::ANY)
        .unwrap()?;
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
}

fn lookup_ct(
    nat: &XdpNat4V4Skel<'_>,
    proto: u8,
    internal_addr: [u8; 4],
    internal_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
) -> Option<types::napt_ct_value> {
    let bytes = nat
        .maps
        .napt_ct
        .lookup(
            as_bytes(&ct_key(internal_addr, internal_port, remote_addr, remote_port, proto)),
            MapFlags::ANY,
        )
        .unwrap()?;
    Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) })
}

fn wait_lan(
    nat: &XdpNat4V4Skel<'_>,
    internal_addr: [u8; 4],
    internal_port: u16,
    proto: u8,
    what: &str,
) {
    wait_for(what, Duration::from_secs(5), || {
        lookup_lan(nat, internal_addr, internal_port, proto).is_some()
    });
}

fn wait_ct(
    nat: &XdpNat4V4Skel<'_>,
    proto: u8,
    internal_addr: [u8; 4],
    internal_port: u16,
    remote_addr: [u8; 4],
    remote_port: u16,
    what: &str,
) {
    wait_for(what, Duration::from_secs(5), || {
        lookup_ct(nat, proto, internal_addr, internal_port, remote_addr, remote_port).is_some()
    });
}

fn push_port(map: &impl MapCore, port: u16, generation: u32) {
    let mut slot = [0u8; 8];
    slot[0..2].copy_from_slice(&port.to_be_bytes());
    slot[4..8].copy_from_slice(&generation.to_ne_bytes());
    let ret = unsafe {
        libbpf_rs::libbpf_sys::bpf_map_update_elem(
            map.as_fd().as_raw_fd(),
            std::ptr::null(),
            slot.as_ptr().cast(),
            0,
        )
    };
    assert_eq!(ret, 0, "queue push failed");
}

fn with_nat<R>(ifindex: u32, wan: [u8; 4], f: impl FnOnce(&XdpNat4V4Skel<'_>) -> R) -> R {
    let mut nat_obj = MaybeUninit::uninit();
    let mut nat_open = XdpNat4V4SkelBuilder::default().open(&mut nat_obj).unwrap();
    {
        let rodata = nat_open.maps.rodata_data.as_deref_mut().unwrap();
        rodata.current_ifindex = ifindex;
        rodata.current_l3_offset = 14;
        rodata.land_nat_external_addr = be32(wan);
        rodata.land_nat_udp_range_start = 32768;
        rodata.land_nat_udp_range_end = 65535;
        rodata.land_nat_tcp_range_start = 32768;
        rodata.land_nat_tcp_range_end = 65535;
    }
    let nat = nat_open.load().unwrap();
    f(&nat)
}

fn build_tcp_pkt(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src_ip, dst_ip, 64)
        .tcp(src_port, dst_port, 1000, 2000);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build packet");
    pkt
}

fn build_tcp_syn_pkt(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = build_tcp_pkt(src_ip, dst_ip, src_port, dst_port);
    pkt[47] = 0x02;
    pkt
}

fn build_udp_pkt(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src_ip, dst_ip, 64)
        .udp(src_port, dst_port);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build udp packet");
    pkt
}

fn build_ipv4_fragment(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    id: u16,
    offset: u16,
    mf: bool,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let l4_hdr_len = if offset == 0 { 20usize } else { 0usize };
    let total_len = 20 + l4_hdr_len + payload.len();
    let mut pkt = vec![0u8; 14 + total_len];

    pkt[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    pkt[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    pkt[12] = 0x08;
    pkt[13] = 0x00;

    let ip_off = 14;
    pkt[ip_off] = 0x45;
    pkt[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[ip_off + 4..ip_off + 6].copy_from_slice(&id.to_be_bytes());
    let mut frag = offset;
    if mf {
        frag |= 0x2000;
    }
    pkt[ip_off + 6..ip_off + 8].copy_from_slice(&frag.to_be_bytes());
    pkt[ip_off + 8] = 64;
    pkt[ip_off + 9] = 6;

    pkt[ip_off + 12..ip_off + 16].copy_from_slice(&src_ip);
    pkt[ip_off + 16..ip_off + 20].copy_from_slice(&dst_ip);

    let mut csum: u32 = 0;
    for i in 0..10 {
        let w = u16::from_be_bytes([pkt[ip_off + i * 2], pkt[ip_off + i * 2 + 1]]) as u32;
        csum += w;
    }
    while csum > 0xffff {
        csum = (csum & 0xffff) + (csum >> 16);
    }
    let csum16 = !(csum as u16);
    pkt[ip_off + 10..ip_off + 12].copy_from_slice(&csum16.to_be_bytes());

    if offset == 0 {
        let tcp_off = ip_off + 20;
        pkt[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
        pkt[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
        pkt[tcp_off + 12] = 0x50;
    }

    pkt[ip_off + 20 + l4_hdr_len..ip_off + 20 + l4_hdr_len + payload.len()]
        .copy_from_slice(payload);

    pkt
}

fn build_ipv4_tcp_syn_frag(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    id: u16,
    offset: u16,
    mf: bool,
) -> Vec<u8> {
    let mut pkt =
        build_ipv4_fragment(src_ip, dst_ip, id, offset, mf, src_port, dst_port, &[0u8; 4]);
    if offset == 0 {
        pkt[34 + 13] = 0x02;
    }
    pkt
}

#[allow(clippy::too_many_arguments)]
fn build_icmp_error_pkt(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    inner_src: [u8; 4],
    inner_dst: [u8; 4],
    inner_sport: u16,
    inner_dport: u16,
    icmp_type: u8,
    icmp_code: u8,
) -> Vec<u8> {
    let eth_hdr = [0x02u8, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
    let inner_ip_start = 14 + 20 + 8;
    let inner_tcp_offset = inner_ip_start + 20;
    let total_len = inner_tcp_offset + 8;
    let ip_total = (total_len - 14) as u16;

    let mut pkt = vec![0u8; total_len];
    pkt[..14].copy_from_slice(&eth_hdr);
    pkt[14] = 0x45;
    pkt[16..18].copy_from_slice(&ip_total.to_be_bytes());
    pkt[20] = 0x40;
    pkt[21] = 0x01;
    pkt[26..30].copy_from_slice(&src_ip);
    pkt[30..34].copy_from_slice(&dst_ip);
    let mut csum: u32 = 0;
    for i in 0..10 {
        csum += u16::from_be_bytes([pkt[14 + i * 2], pkt[15 + i * 2]]) as u32;
    }
    while csum > 0xffff {
        csum = (csum & 0xffff) + (csum >> 16);
    }
    pkt[24..26].copy_from_slice(&(!(csum as u16)).to_be_bytes());
    pkt[34] = icmp_type;
    pkt[35] = icmp_code;

    let inner = &mut pkt[inner_ip_start..];
    inner[0] = 0x45;
    let inner_total = (inner.len()) as u16;
    inner[2..4].copy_from_slice(&inner_total.to_be_bytes());
    inner[6] = 0x40;
    inner[7] = 0x06;
    inner[12..16].copy_from_slice(&inner_src);
    inner[16..20].copy_from_slice(&inner_dst);
    let mut inner_csum: u32 = 0;
    for i in 0..10 {
        inner_csum += u16::from_be_bytes([inner[i * 2], inner[i * 2 + 1]]) as u32;
    }
    while inner_csum > 0xffff {
        inner_csum = (inner_csum & 0xffff) + (inner_csum >> 16);
    }
    inner[10..12].copy_from_slice(&(!(inner_csum as u16)).to_be_bytes());
    let tcp = &mut pkt[inner_tcp_offset..];
    tcp[0..2].copy_from_slice(&inner_sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&inner_dport.to_be_bytes());
    pkt
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_static_egress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        seed_static(nat, PROTO_TCP, LAN_IP, 80, 8080);

        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();

        let pkt = build_tcp_syn_pkt(LAN_IP, REMOTE_IP, 80, 9999);
        send_raw_packet(nat_p, &pkt);

        wait_ct(nat, PROTO_TCP, LAN_IP, 80, REMOTE_IP, 9999, "static egress ct");
        let lan = lookup_lan(nat, LAN_IP, 80, PROTO_TCP).expect("static lan mapping");
        assert_eq!(lan.external_port, 8080u16.to_be());
        assert_eq!(lan.kind, KIND_STATIC);
        let wan = lookup_wan(nat, PROTO_TCP, 8080).expect("static wan mapping");
        assert_eq!(wan.internal_addr, be32(LAN_IP));
        assert_eq!(wan.internal_port, 80u16.to_be());
        assert_eq!(wan.kind, KIND_STATIC);
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_static_ingress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        seed_static(nat, PROTO_TCP, LAN_IP, 80, 8080);

        let _l0 = nat.progs.ingress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();

        let pkt = build_tcp_syn_pkt(REMOTE_IP, WAN_IP, 9999, 8080);
        send_raw_packet(nat_p, &pkt);

        wait_ct(nat, PROTO_TCP, LAN_IP, 80, REMOTE_IP, 9999, "static ingress ct");
        let ct = lookup_ct(nat, PROTO_TCP, LAN_IP, 80, REMOTE_IP, 9999).expect("static ct");
        assert_eq!(ct.is_static, 1);
        assert_eq!(ct.status, CT_ACTIVE);
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_dynamic_egress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        push_port(&nat.maps.napt_tcp_ports, 0x1000, 0);

        let pkt = build_tcp_syn_pkt(REMOTE_IP, [93, 184, 216, 34], 12345, 80);
        send_raw_packet(nat_p, &pkt);

        wait_lan(nat, REMOTE_IP, 12345, PROTO_TCP, "egress dyn lan mapping");
        let lan = lookup_lan(nat, REMOTE_IP, 12345, PROTO_TCP).expect("dyn lan mapping");
        assert_eq!(lan.external_port, 4096u16.to_be());
        assert_eq!(lan.kind, KIND_DYNAMIC);
        let wan = lookup_wan(nat, PROTO_TCP, 4096).expect("dyn wan mapping");
        assert_eq!(wan.internal_addr, be32(REMOTE_IP));
        assert_eq!(wan.internal_port, 12345u16.to_be());

        wait_ct(nat, PROTO_TCP, REMOTE_IP, 12345, [93, 184, 216, 34], 80, "egress dyn ct");
        let ct =
            lookup_ct(nat, PROTO_TCP, REMOTE_IP, 12345, [93, 184, 216, 34], 80).expect("dyn ct");
        assert_eq!(ct.status, CT_ACTIVE);

        let mut cleanup = ct;
        cleanup.status = 50;
        nat.maps
            .napt_ct
            .update(
                as_bytes(&ct_key(REMOTE_IP, 12345, [93, 184, 216, 34], 80, PROTO_TCP)),
                as_bytes(&cleanup),
                MapFlags::ANY,
            )
            .unwrap();

        send_raw_packet(nat_p, &pkt);
        settle(300);

        let ct = lookup_ct(nat, PROTO_TCP, REMOTE_IP, 12345, [93, 184, 216, 34], 80)
            .expect("cleanup ct should remain");
        assert_eq!(ct.status, 50, "XDP egress must not reactivate cleanup CT");
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_firewall_pipeline() {
    let pair = VethPair::create("nf");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();
    let nat_p_i = pair.peer_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let mut fw_obj = MaybeUninit::uninit();
        let fw = XdpFirewallSkelBuilder::default().open(&mut fw_obj).unwrap().load().unwrap();
        let mut d_obj = MaybeUninit::uninit();
        let dummy = TestXdpDummySkelBuilder::default().open(&mut d_obj).unwrap().load().unwrap();

        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

        let fw_lan_fd = fw.progs.xdp_firewall_lan_v4.as_fd().as_raw_fd();
        nat.maps
            .next_stage
            .update(&0u32.to_ne_bytes(), &fw_lan_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
        nat.maps
            .xdp_pipe_exits_lan
            .update(&0u32.to_ne_bytes(), &fw_lan_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();

        seed_static(nat, PROTO_TCP, LAN_IP, 80, 8080);

        let pkt = build_tcp_syn_pkt(LAN_IP, REMOTE_IP, 80, 9999);
        send_raw_packet(nat_p, &pkt);

        wait_ct(nat, PROTO_TCP, LAN_IP, 80, REMOTE_IP, 9999, "pipeline ct");

        let block_action = 1u32.to_le_bytes();
        let mut fw_key = [0u8; 8];
        fw_key[0..4].copy_from_slice(&32u32.to_le_bytes());
        fw_key[4..8].copy_from_slice(&WAN_IP);
        fw.maps.firewall_block_ip4_map.update(&fw_key, &block_action, MapFlags::ANY).unwrap();

        send_raw_packet(nat_p, &pkt);
        assert!(fw.maps.firewall_block_ip4_map.lookup(&fw_key, MapFlags::ANY).unwrap().is_some());

        drop(fw);
        drop(dummy);
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_fragment_v4() {
    let pid = crate::tests::test_id();
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();
    let frag_id = (pid & 0xffff) as u16;

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        push_port(&nat.maps.napt_tcp_ports, 0x2000, 0);

        let syn_frag =
            build_ipv4_tcp_syn_frag(REMOTE_IP, [93, 184, 216, 34], 22345, 80, frag_id, 0, true);
        send_raw_packet(nat_p, &syn_frag);

        wait_lan(nat, REMOTE_IP, 22345, PROTO_TCP, "frag egress lan mapping");
        let lan = lookup_lan(nat, REMOTE_IP, 22345, PROTO_TCP).expect("frag lan mapping");
        assert_eq!(lan.external_port, 8192u16.to_be());
        let wan = lookup_wan(nat, PROTO_TCP, 8192).expect("frag wan mapping");
        assert_eq!(wan.internal_addr, be32(REMOTE_IP));
        assert_eq!(wan.internal_port, 22345u16.to_be());
        wait_ct(nat, PROTO_TCP, REMOTE_IP, 22345, [93, 184, 216, 34], 80, "frag ct");
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_ct_dynamic_multi_pkt() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        push_port(&nat.maps.napt_tcp_ports, 0x3000, 0);

        let syn_pkt = build_tcp_syn_pkt([10, 0, 0, 2], [93, 184, 216, 34], 33445, 80);
        send_raw_packet(nat_p, &syn_pkt);

        wait_lan(nat, [10, 0, 0, 2], 33445, PROTO_TCP, "multi lan mapping");
        let lan = lookup_lan(nat, [10, 0, 0, 2], 33445, PROTO_TCP).expect("multi lan mapping");
        assert_eq!(lan.external_port, 12288u16.to_be());
        wait_ct(nat, PROTO_TCP, [10, 0, 0, 2], 33445, [93, 184, 216, 34], 80, "multi ct");
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_fragment_ingress() {
    let pid = crate::tests::test_id();
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();
    let frag_id = (pid & 0xffff) as u16;

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.ingress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        seed_dynamic(nat, PROTO_TCP, [10, 0, 0, 3], 12345, 4097, [0, 0, 0, 0], 0, 0, 1, 1);

        let pkt =
            build_ipv4_tcp_syn_frag([93, 184, 216, 34], WAN_IP, 33446, 4097, frag_id, 0, true);
        send_raw_packet(nat_p, &pkt);

        wait_ct(nat, PROTO_TCP, [10, 0, 0, 3], 12345, [93, 184, 216, 34], 33446, "frag in ct");
        let ct = lookup_ct(nat, PROTO_TCP, [10, 0, 0, 3], 12345, [93, 184, 216, 34], 33446)
            .expect("frag in ct");
        assert_eq!(ct.status, CT_ACTIVE);
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_dynamic_ingress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.ingress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        seed_dynamic(nat, PROTO_TCP, [10, 0, 0, 5], 22222, 9090, [0, 0, 0, 0], 0, 0, 1, 1);

        let pkt = build_tcp_pkt([93, 184, 216, 34], WAN_IP, 8888, 9090);
        send_raw_packet(nat_p, &pkt);
        settle(300);

        let wan = lookup_wan(nat, PROTO_TCP, 9090).expect("dyn ingress mapping preserved");
        assert_eq!(wan.internal_addr, be32([10, 0, 0, 5]));
        assert_eq!(wan.internal_port, 22222u16.to_be());
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_udp_egress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        push_port(&nat.maps.napt_udp_ports, 0x5000, 0);

        let pkt = build_udp_pkt([10, 0, 0, 6], [93, 184, 216, 34], 22345, 53);
        send_raw_packet(nat_p, &pkt);

        wait_lan(nat, [10, 0, 0, 6], 22345, PROTO_UDP, "udp egress lan mapping");
        let lan = lookup_lan(nat, [10, 0, 0, 6], 22345, PROTO_UDP).expect("udp lan mapping");
        assert_eq!(lan.external_port, 20480u16.to_be());
        wait_ct(nat, PROTO_UDP, [10, 0, 0, 6], 22345, [93, 184, 216, 34], 53, "udp egress ct");
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_udp_ingress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.ingress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        seed_dynamic(nat, PROTO_UDP, [10, 0, 0, 7], 33445, 9091, [0, 0, 0, 0], 0, 0, 1, 1);

        let pkt = build_udp_pkt([93, 184, 216, 34], WAN_IP, 53, 9091);
        send_raw_packet(nat_p, &pkt);

        wait_ct(nat, PROTO_UDP, [10, 0, 0, 7], 33445, [93, 184, 216, 34], 53, "udp ingress ct");
        let ct = lookup_ct(nat, PROTO_UDP, [10, 0, 0, 7], 33445, [93, 184, 216, 34], 53)
            .expect("udp ingress ct");
        assert_eq!(ct.status, CT_ACTIVE);
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_fragment_middle() {
    let pid = crate::tests::test_id();
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();
    let frag_id = (pid & 0xffff) as u16;

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        push_port(&nat.maps.napt_tcp_ports, 0x6000, 0);

        let first =
            build_ipv4_tcp_syn_frag([10, 0, 0, 8], [93, 184, 216, 34], 22348, 80, frag_id, 0, true);
        send_raw_packet(nat_p, &first);

        wait_lan(nat, [10, 0, 0, 8], 22348, PROTO_TCP, "middle first mapping");

        let middle = build_ipv4_fragment(
            [10, 0, 0, 8],
            [93, 184, 216, 34],
            frag_id,
            8,
            true,
            0,
            0,
            &[0u8; 20],
        );
        send_raw_packet(nat_p, &middle);
        settle(300);

        let lan = lookup_lan(nat, [10, 0, 0, 8], 22348, PROTO_TCP).expect("middle mapping");
        assert_eq!(lan.external_port, 0x6000u16.to_be(), "middle must reuse the first mapping");
        assert_eq!(lan.kind, KIND_DYNAMIC);
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_icmp_error_egress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        seed_static(nat, PROTO_ICMP, [192, 168, 1, 200], 0, 0);

        let pkt = build_icmp_error_pkt(
            [192, 168, 1, 200],
            REMOTE_IP,
            [192, 168, 1, 200],
            REMOTE_IP,
            12345,
            80,
            3,
            0,
        );
        send_raw_packet(nat_p, &pkt);
        settle(300);

        let lan = lookup_lan(nat, [192, 168, 1, 200], 0, PROTO_ICMP).expect("icmp lan mapping");
        assert_eq!(lan.kind, KIND_STATIC);
        let wan = lookup_wan(nat, PROTO_ICMP, 0).expect("icmp wan mapping");
        assert_eq!(wan.internal_addr, be32([192, 168, 1, 200]));
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_static_ingress_mark() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let mut d_obj = MaybeUninit::uninit();
        let dummy = TestXdpDummySkelBuilder::default().open(&mut d_obj).unwrap().load().unwrap();

        let _l0 = nat.progs.ingress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
        nat.maps
            .next_stage
            .update(&2u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();

        seed_static(nat, PROTO_TCP, LAN_IP, 80, 8080);

        let pkt = build_tcp_syn_pkt(REMOTE_IP, WAN_IP, 9999, 8080);
        send_raw_packet(nat_p, &pkt);

        wait_ct(nat, PROTO_TCP, LAN_IP, 80, REMOTE_IP, 9999, "static ingress mark ct");
        wait_for("static ingress mark", Duration::from_secs(5), || {
            dummy
                .maps
                .dummy_meta_map
                .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
                .unwrap()
                .is_some_and(|v| v[0] == 1)
        });

        drop(dummy);
    });
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_chain_pipeline() {
    let pair = VethPair::create("nc");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();
    let nat_p_i = pair.peer_ifindex();

    with_nat(nat_h_i, WAN_IP, |nat| {
        let mut fw_obj = MaybeUninit::uninit();
        let fw = XdpFirewallSkelBuilder::default().open(&mut fw_obj).unwrap().load().unwrap();
        let mut d_obj = MaybeUninit::uninit();
        let dummy = TestXdpDummySkelBuilder::default().open(&mut d_obj).unwrap().load().unwrap();

        let _l0 = nat.progs.egress_nat_v4_v4.attach_xdp(nat_h_i as i32).unwrap();
        let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

        let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
        let fw_lan_fd = fw.progs.xdp_firewall_lan_v4.as_fd().as_raw_fd();

        nat.maps
            .next_stage
            .update(&0u32.to_ne_bytes(), &fw_lan_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
        fw.maps
            .next_stage
            .update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
        nat.maps
            .xdp_pipe_exits_lan
            .update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();
        fw.maps
            .xdp_pipe_exits_lan
            .update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
            .unwrap();

        seed_static(nat, PROTO_TCP, LAN_IP, 80, 8080);

        let pkt = build_tcp_syn_pkt(LAN_IP, REMOTE_IP, 80, 9999);
        send_raw_packet(nat_p, &pkt);

        wait_ct(nat, PROTO_TCP, LAN_IP, 80, REMOTE_IP, 9999, "chain ct");

        let block_action = 1u32.to_le_bytes();
        let mut fw_key = [0u8; 8];
        fw_key[0..4].copy_from_slice(&32u32.to_le_bytes());
        fw_key[4..8].copy_from_slice(&WAN_IP);
        fw.maps.firewall_block_ip4_map.update(&fw_key, &block_action, MapFlags::ANY).unwrap();

        send_raw_packet(nat_p, &pkt);
        assert!(fw.maps.firewall_block_ip4_map.lookup(&fw_key, MapFlags::ANY).unwrap().is_some());

        drop(fw);
        drop(dummy);
    });
}

fn build_tcp6_pkt(src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
    use etherparse::PacketBuilder;
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv6(src, dst, 64)
        .tcp(src_port, dst_port, 1000, 2000);
    let payload = [0u8; 8];
    let mut pkt = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut pkt, &payload).expect("build v6 packet");
    pkt
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_v6_egress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    let share_pin = crate::tests::isolated_pin_root("xdp-nat-nat6e");
    let maps = crate::tests::init_shared_maps_for_test(&share_pin);
    let mut nat_b = XdpNat6SkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    nat_open.maps.rodata_data.as_deref_mut().unwrap().wan_ro_prefix6.b =
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0];
    nat_open.maps.rodata_data.as_deref_mut().unwrap().wan_ro_npt_mask =
        crate::maps::wan::compute_npt_mask(48);
    let nat = nat_open.load().unwrap();

    let _l0 = nat.progs.egress_nat_v6.attach_xdp(nat_h_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    wan_key[4] = 1;
    let mut wan_val = [0u8; 48];
    wan_val[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    wan_val[16..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    wan_val[32] = 48;
    wan_val[40..48].copy_from_slice(&crate::maps::wan::compute_npt_mask(48).to_le_bytes());
    maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let lan_prefix = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = build_tcp6_pkt(lan_prefix, dst, 12345, 80);
    send_raw_packet(nat_p, &pkt);

    wait_for("wan ip binding entry", Duration::from_secs(5), || {
        let mut k = [0u8; 8];
        k[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
        k[4] = 1;
        maps.wan_ip_binding.lookup(&k, MapFlags::ANY).unwrap().is_some()
    });

    drop(nat);
    drop(maps);
}

#[ignore = "requires root and veth pairs; run with --include-ignored"]
#[test]
fn xdp_nat_v6_ingress() {
    let pair = VethPair::create("nat");
    let nat_p = pair.peer();
    let nat_h_i = pair.host_ifindex();

    let share_pin = crate::tests::isolated_pin_root("xdp-nat-nat6ie");
    let maps = crate::tests::init_shared_maps_for_test(&share_pin);
    let mut nat_b = XdpNat6SkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    nat_open.maps.rodata_data.as_deref_mut().unwrap().wan_ro_prefix6.b =
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0];
    nat_open.maps.rodata_data.as_deref_mut().unwrap().wan_ro_npt_mask =
        crate::maps::wan::compute_npt_mask(48);
    let nat = nat_open.load().unwrap();

    let _l0 = nat.progs.ingress_nat_v6.attach_xdp(nat_h_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    wan_key[4] = 1;
    let mut wan_val = [0u8; 48];
    wan_val[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    wan_val[16..24].copy_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0]);
    wan_val[32] = 48;
    wan_val[40..48].copy_from_slice(&crate::maps::wan::compute_npt_mask(48).to_le_bytes());
    maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let wan_src = [0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let wan_dst = [0x20, 0x01, 0x0d, 0xb8, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let pkt = build_tcp6_pkt(wan_src, wan_dst, 9999, 8080);
    send_raw_packet(nat_p, &pkt);

    wait_for("wan ip binding entry", Duration::from_secs(5), || {
        let mut k = [0u8; 8];
        k[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
        k[4] = 1;
        maps.wan_ip_binding.lookup(&k, MapFlags::ANY).unwrap().is_some()
    });

    drop(nat);
    drop(maps);
}
