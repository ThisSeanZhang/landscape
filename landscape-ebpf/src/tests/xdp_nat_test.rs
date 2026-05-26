use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;

use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder as _},
    MapCore, MapFlags,
};
use nix::net::if_::if_nametoindex;

use crate::map_setting::share_map::ShareMapSkelBuilder;
use crate::tests::test_xdp_dummy::TestXdpDummySkelBuilder;
use crate::tests::xdp_firewall_skel::XdpFirewallSkelBuilder;
use crate::tests::xdp_lan_chain_skel::XdpLanChainSkelBuilder;
use crate::tests::xdp_nat_skel::XdpNatSkelBuilder;

use std::os::fd::{AsFd, AsRawFd};
use std::sync::Mutex;

static XDP_NAT_LOCK: Mutex<()> = Mutex::new(());

fn pin_root(prefix: &str) -> PathBuf {
    let path = PathBuf::from(format!(
        "/sys/fs/bpf/landscape-test/xdp-nat-{}-{}-{}",
        prefix,
        std::process::id(),
        crate::tests::test_id()
    ));
    let _ = std::fs::create_dir_all(&path);
    path
}

fn send_raw_packet(iface: &str, pkt: &[u8]) {
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(0x0300)),
    )
    .expect("create raw socket");
    let idx = if_nametoindex(iface).expect("if_nametoindex");
    let addr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: 0x0300u16.to_be(),
        sll_ifindex: idx as i32,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0u8; 8],
    };
    unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            pkt.as_ptr() as *const libc::c_void,
            pkt.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        );
    }
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

fn write_static_mapping_v4(
    map: &libbpf_rs::MapMut,
    gress: u8,
    l4proto: u8,
    from_port: u16,
    from_addr: [u8; 4],
    to_addr: [u8; 4],
    to_port: u16,
    is_static: u8,
) {
    let mut k = [0u8; 8];
    k[0] = gress;
    k[1] = l4proto;
    k[2..4].copy_from_slice(&from_port.to_be_bytes());
    k[4..8].copy_from_slice(&from_addr);

    let mut v = [0u8; 24];
    v[8..12].copy_from_slice(&to_addr);
    v[16..18].copy_from_slice(&to_port.to_be_bytes());
    v[22] = is_static;

    map.update(&k, &v, MapFlags::ANY).unwrap();
}

fn lookup_nat4_mapping(
    map: &libbpf_rs::MapMut,
    gress: u8,
    l4proto: u8,
    from_port: u16,
    from_addr: [u8; 4],
) -> Option<Vec<u8>> {
    let mut k = [0u8; 8];
    k[0] = gress;
    k[1] = l4proto;
    k[2..4].copy_from_slice(&from_port.to_be_bytes());
    k[4..8].copy_from_slice(&from_addr);
    map.lookup(&k, MapFlags::ANY).ok().flatten()
}

fn assert_dyn_map_entry(
    map: &libbpf_rs::MapMut,
    gress: u8,
    l4proto: u8,
    from_port: u16,
    from_addr: [u8; 4],
    expected_addr: [u8; 4],
    expected_port: u16,
) {
    let val = lookup_nat4_mapping(map, gress, l4proto, from_port, from_addr)
        .expect(&format!("dyn map entry should exist: gress={gress} l4={l4proto} port={from_port} addr={from_addr:?}"));
    let addr = [val[8], val[9], val[10], val[11]];
    let port = u16::from_be_bytes([val[16], val[17]]);
    assert_eq!(addr, expected_addr, "nat addr mismatch");
    assert_eq!(port, expected_port, "nat port mismatch");
}

fn assert_static_map_entry(
    map: &libbpf_rs::MapMut,
    gress: u8,
    l4proto: u8,
    from_port: u16,
    from_addr: [u8; 4],
    expected_addr: [u8; 4],
    expected_port: u16,
) {
    let val = lookup_nat4_mapping(map, gress, l4proto, from_port, from_addr)
        .expect(&format!("static map entry should exist: gress={gress} l4={l4proto} port={from_port} addr={from_addr:?}"));
    let addr = [val[8], val[9], val[10], val[11]];
    let port = u16::from_be_bytes([val[16], val[17]]);
    let is_static = val[22];
    assert_eq!(addr, expected_addr, "nat addr mismatch");
    assert_eq!(port, expected_port, "nat port mismatch");
    assert_eq!(is_static, 1, "is_static should be 1");
}

fn assert_no_dyn_map_entry(
    map: &libbpf_rs::MapMut,
    gress: u8,
    l4proto: u8,
    from_port: u16,
    from_addr: [u8; 4],
) {
    let result = lookup_nat4_mapping(map, gress, l4proto, from_port, from_addr);
    assert!(result.is_none(), "expected no dyn map entry for gress={gress} l4={l4proto} port={from_port} addr={from_addr:?}");
}

fn assert_wan_ip_binding(
    map: &libbpf_rs::MapMut,
    ifindex: u32,
    l3proto: u8,
    expected_wan: &[u8],
    expected_gateway: &[u8],
    expected_prefix: u8,
    expected_mask: &[u8],
) {
    let mut k = [0u8; 8];
    k[0..4].copy_from_slice(&ifindex.to_ne_bytes());
    k[4] = l3proto;
    let val = map
        .lookup(&k, MapFlags::ANY)
        .expect("wan_ip_binding lookup failed")
        .expect("wan_ip_binding entry should exist");
    assert_eq!(&val[0..8], expected_wan, "wan addr mismatch");
    assert_eq!(&val[16..24], expected_gateway, "gateway mismatch");
    assert_eq!(val[32], expected_prefix, "prefix len mismatch");
    assert_eq!(&val[40..48], expected_mask, "npt mask mismatch");
}

#[test]
fn xdp_nat_static_egress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}e"), format!("natp{pid}e"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let _nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("nat4e");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
    nat.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();

    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
        1,
    );
    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
        1,
    );

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let pkt = build_tcp_pkt([192, 168, 1, 100], [10, 0, 0, 1], 80, 9999);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
    );
    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
    );

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_static_ingress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}i"), format!("natp{pid}i"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;

    let share_pin = pin_root("nat4i");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.ingress_nat.attach_xdp(nat_h_i as i32).unwrap();

    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
        1,
    );

    let pkt = build_tcp_pkt([10, 0, 0, 1], [203, 0, 113, 1], 9999, 8080);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
    );

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_dynamic_egress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}d"), format!("natp{pid}d"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("nat4dyn");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let port_be = 0x1000u16.to_be_bytes();
    let tcp_queue_fd = nat.maps.nat4_tcp_free_ports_v3.as_fd().as_raw_fd();
    for _ in 0..10 {
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                tcp_queue_fd,
                std::ptr::null(),
                port_be.as_ptr() as *const libc::c_void,
                0,
            )
        };
        if ret != 0 {
            break;
        }
    }

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let pkt = build_tcp_syn_pkt([10, 0, 0, 1], [93, 184, 216, 34], 12345, 80);
    for _ in 0..3 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        1,
        6,
        12345,
        [10, 0, 0, 1],
        [203, 0, 113, 1],
        4096,
    );
    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        0,
        6,
        4096,
        [203, 0, 113, 1],
        [10, 0, 0, 1],
        12345,
    );

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
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

#[test]
fn xdp_nat_v6_egress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}v6"), format!("natp{pid}v6"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;

    let share_pin = pin_root("nat6e");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    wan_key[4] = 1;
    let mut wan_val = [0u8; 48];
    wan_val[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    wan_val[16..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    wan_val[32] = 48;
    wan_val[40..48].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let lan_prefix = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let pkt = build_tcp6_pkt(lan_prefix, dst, 12345, 80);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_wan_ip_binding(
        &share.maps.wan_ip_binding,
        nat_h_i,
        1,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
        48,
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
    );

    drop(nat);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_firewall_pipeline() {
    let _lock = XDP_NAT_LOCK.lock().unwrap();
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nfh{pid}"), format!("nfp{pid}"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("pipeline");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let mut fw_b = XdpFirewallSkelBuilder::default();
    fw_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut fw_obj = std::mem::MaybeUninit::uninit();
    let fw = fw_b.open(&mut fw_obj).unwrap().load().unwrap();

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let _nat_lan_fd = nat.progs.egress_nat.as_fd().as_raw_fd();
    let fw_lan_fd = fw.progs.xdp_firewall_lan.as_fd().as_raw_fd();

    nat.maps
        .next_stage
        .update(&0u32.to_ne_bytes(), &fw_lan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    nat.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &fw_lan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
        1,
    );
    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
        1,
    );

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let pkt = build_tcp_pkt([192, 168, 1, 100], [10, 0, 0, 1], 80, 9999);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
    );
    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
    );

    let block_action = 1u32.to_le_bytes();
    let mut fw_key = [0u8; 8];
    fw_key[0..4].copy_from_slice(&32u32.to_le_bytes());
    fw_key[4..8].copy_from_slice(&[203, 0, 113, 1]);
    fw.maps.firewall_block_ip4_map.update(&fw_key, &block_action, MapFlags::ANY).unwrap();

    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
    );
    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
    );
    let block_val = fw
        .maps
        .firewall_block_ip4_map
        .lookup(&fw_key, MapFlags::ANY)
        .expect("lookup block")
        .expect("block entry should exist");
    assert_eq!(&block_val[0..4], &block_action, "block action should be set");

    drop(fw);
    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
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
    pkt[ip_off + 1] = 0;
    pkt[ip_off + 2..ip_off + 4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[ip_off + 4..ip_off + 6].copy_from_slice(&id.to_be_bytes());
    let mut frag = offset;
    if mf {
        frag |= 0x2000;
    }
    pkt[ip_off + 6..ip_off + 8].copy_from_slice(&frag.to_be_bytes());
    pkt[ip_off + 8] = 64;
    pkt[ip_off + 9] = 6;
    pkt[ip_off + 10..ip_off + 12].copy_from_slice(&[0u8; 2]);

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
        pkt[tcp_off + 4..tcp_off + 8].copy_from_slice(&0u32.to_be_bytes());
        pkt[tcp_off + 12] = 0x50;
        pkt[tcp_off + 13] = 0x00;
        pkt[tcp_off + 14..tcp_off + 16].copy_from_slice(&0u16.to_be_bytes());
        pkt[tcp_off + 16..tcp_off + 20].copy_from_slice(&0u32.to_be_bytes());
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
        let tcp_off = 34;
        pkt[tcp_off + 13] = 0x02;
    }
    pkt
}

#[test]
fn xdp_nat_fragment_v4() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}f4"), format!("natp{pid}f4"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;

    let share_pin = pin_root("frag4e");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let port_be = 0x2000u16.to_be_bytes();
    let tcp_queue_fd = nat.maps.nat4_tcp_free_ports_v3.as_fd().as_raw_fd();
    for _ in 0..10 {
        unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                tcp_queue_fd,
                std::ptr::null(),
                port_be.as_ptr() as *const libc::c_void,
                0,
            )
        };
    }

    let frag_id = (pid & 0xffff) as u16;

    let syn_frag =
        build_ipv4_tcp_syn_frag([10, 0, 0, 1], [93, 184, 216, 34], 22345, 80, frag_id, 0, true);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &syn_frag);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        1,
        6,
        22345,
        [10, 0, 0, 1],
        [203, 0, 113, 1],
        8192,
    );
    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        0,
        6,
        8192,
        [203, 0, 113, 1],
        [10, 0, 0, 1],
        22345,
    );

    drop(nat);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_v6_ingress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}v6i"), format!("natp{pid}v6i"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;

    let share_pin = pin_root("nat6ie");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let _l0 = nat.progs.ingress_nat.attach_xdp(nat_h_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    wan_key[4] = 1;
    let mut wan_val = [0u8; 48];
    wan_val[0..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);
    wan_val[16..24].copy_from_slice(&[0xfd, 0x00, 0, 0, 0, 0, 0, 0]);
    wan_val[32] = 48;
    wan_val[40..48].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let wan_src = [0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let wan_dst = [0x20, 0x01, 0x0d, 0xb8, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let pkt = build_tcp6_pkt(wan_src, wan_dst, 9999, 8080);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_wan_ip_binding(
        &share.maps.wan_ip_binding,
        nat_h_i,
        1,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
        &[0xfd, 0x00, 0, 0, 0, 0, 0, 0],
        48,
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
    );

    drop(nat);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_ct_dynamic_multi_pkt() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}ct"), format!("natp{pid}ct"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;

    let share_pin = pin_root("ctmulti");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let port_be = 0x3000u16.to_be_bytes();
    let tcp_queue_fd = nat.maps.nat4_tcp_free_ports_v3.as_fd().as_raw_fd();
    for _ in 0..10 {
        unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                tcp_queue_fd,
                std::ptr::null(),
                port_be.as_ptr() as *const libc::c_void,
                0,
            )
        };
    }

    let syn_pkt = build_tcp_syn_pkt([10, 0, 0, 2], [93, 184, 216, 34], 33445, 80);
    for _ in 0..3 {
        send_raw_packet(&nat_p, &syn_pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        1,
        6,
        33445,
        [10, 0, 0, 2],
        [203, 0, 113, 1],
        12288,
    );
    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        0,
        6,
        12288,
        [203, 0, 113, 1],
        [10, 0, 0, 2],
        33445,
    );

    drop(nat);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

fn write_dyn_mapping_v4(
    map: &libbpf_rs::MapMut,
    gress: u8,
    l4proto: u8,
    from_port: u16,
    from_addr: [u8; 4],
    to_addr: [u8; 4],
    to_port: u16,
) {
    let mut k = [0u8; 8];
    k[0] = gress;
    k[1] = l4proto;
    k[2..4].copy_from_slice(&from_port.to_be_bytes());
    k[4..8].copy_from_slice(&from_addr);

    let mut v = [0u8; 24];
    v[8..12].copy_from_slice(&to_addr);
    v[16..18].copy_from_slice(&to_port.to_be_bytes());

    map.update(&k, &v, MapFlags::ANY).unwrap();
}

fn write_frag_cache_entry(
    map: &libbpf_rs::MapMut,
    l3proto: u8,
    l4proto: u8,
    frag_id: u32,
    saddr: [u8; 16],
    daddr: [u8; 16],
    sport: u16,
    dport: u16,
) {
    let mut k = [0u8; 40];
    k[0] = l3proto;
    k[1] = l4proto;
    k[4..8].copy_from_slice(&frag_id.to_be_bytes());
    k[8..24].copy_from_slice(&saddr);
    k[24..40].copy_from_slice(&daddr);

    let mut v = [0u8; 4];
    v[0..2].copy_from_slice(&sport.to_be_bytes());
    v[2..4].copy_from_slice(&dport.to_be_bytes());

    map.update(&k, &v, MapFlags::ANY).unwrap();
}

#[test]
fn xdp_nat_fragment_ingress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}fi"), format!("natp{pid}fi"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("fragin");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.ingress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    write_dyn_mapping_v4(
        &nat.maps.nat4_dyn_map,
        1,
        6,
        12345,
        [10, 0, 0, 3],
        [203, 0, 113, 1],
        4097,
    );
    write_dyn_mapping_v4(
        &nat.maps.nat4_dyn_map,
        0,
        6,
        4097,
        [203, 0, 113, 1],
        [10, 0, 0, 3],
        12345,
    );

    let frag_id = (pid & 0xffff) as u32;

    let mut saddr6 = [0u8; 16];
    saddr6[12..16].copy_from_slice(&[93, 184, 216, 34]);
    let mut daddr6 = [0u8; 16];
    daddr6[12..16].copy_from_slice(&[203, 0, 113, 1]);
    write_frag_cache_entry(&nat.maps.frag_cache, 0, 6, frag_id, saddr6, daddr6, 80u16, 4097u16);

    let pkt = build_ipv4_tcp_syn_frag(
        [93, 184, 216, 34],
        [203, 0, 113, 1],
        33446,
        4097,
        frag_id as u16,
        0,
        true,
    );
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        1,
        6,
        12345,
        [10, 0, 0, 3],
        [203, 0, 113, 1],
        4097,
    );
    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        0,
        6,
        4097,
        [203, 0, 113, 1],
        [10, 0, 0, 3],
        12345,
    );

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
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

#[test]
fn xdp_nat_dynamic_ingress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}di"), format!("natp{pid}di"));
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("nat4dyn_i");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();
    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();
    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.ingress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    write_dyn_mapping_v4(
        &nat.maps.nat4_dyn_map,
        1,
        6,
        22222,
        [10, 0, 0, 5],
        [203, 0, 113, 1],
        9090,
    );
    write_dyn_mapping_v4(
        &nat.maps.nat4_dyn_map,
        0,
        6,
        9090,
        [203, 0, 113, 1],
        [10, 0, 0, 5],
        22222,
    );

    let pkt = build_tcp_pkt([93, 184, 216, 34], [203, 0, 113, 1], 8888, 9090);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        1,
        6,
        22222,
        [10, 0, 0, 5],
        [203, 0, 113, 1],
        9090,
    );
    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        0,
        6,
        9090,
        [203, 0, 113, 1],
        [10, 0, 0, 5],
        22222,
    );

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_udp_egress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}ue"), format!("natp{pid}ue"));
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("udp_eg");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();
    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();
    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let port_be = 0x5000u16.to_be_bytes();
    let udp_queue_fd = nat.maps.nat4_udp_free_ports_v3.as_fd().as_raw_fd();
    for _ in 0..10 {
        unsafe {
            libbpf_rs::libbpf_sys::bpf_map_update_elem(
                udp_queue_fd,
                std::ptr::null(),
                port_be.as_ptr() as *const libc::c_void,
                0,
            )
        };
    }

    let pkt = build_udp_pkt([10, 0, 0, 6], [93, 184, 216, 34], 22345, 53);
    for _ in 0..3 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        1,
        17,
        22345,
        [10, 0, 0, 6],
        [203, 0, 113, 1],
        20480,
    );
    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        0,
        17,
        20480,
        [203, 0, 113, 1],
        [10, 0, 0, 6],
        22345,
    );

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_udp_ingress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}ui"), format!("natp{pid}ui"));
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("udp_in");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();
    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();
    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.ingress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    write_dyn_mapping_v4(
        &nat.maps.nat4_dyn_map,
        1,
        17,
        33445,
        [10, 0, 0, 7],
        [203, 0, 113, 1],
        9091,
    );
    write_dyn_mapping_v4(
        &nat.maps.nat4_dyn_map,
        0,
        17,
        9091,
        [203, 0, 113, 1],
        [10, 0, 0, 7],
        33445,
    );

    let pkt = build_udp_pkt([93, 184, 216, 34], [203, 0, 113, 1], 53, 9091);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        1,
        17,
        33445,
        [10, 0, 0, 7],
        [203, 0, 113, 1],
        9091,
    );
    assert_dyn_map_entry(
        &nat.maps.nat4_dyn_map,
        0,
        17,
        9091,
        [203, 0, 113, 1],
        [10, 0, 0, 7],
        33445,
    );

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_fragment_middle() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}fm"), format!("natp{pid}fm"));
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("fragmid");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();
    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();
    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let frag_id = (pid & 0xffff) as u16;

    let first =
        build_ipv4_tcp_syn_frag([10, 0, 0, 8], [93, 184, 216, 34], 22348, 80, frag_id, 0, true);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &first);
        thread::sleep(Duration::from_millis(10));
    }

    let middle =
        build_ipv4_fragment([10, 0, 0, 8], [93, 184, 216, 34], frag_id, 8, true, 0, 0, &[0u8; 20]);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &middle);
        thread::sleep(Duration::from_millis(10));
    }
    thread::sleep(Duration::from_millis(300));

    assert_no_dyn_map_entry(&nat.maps.nat4_dyn_map, 1, 6, 22348, [10, 0, 0, 8]);

    drop(nat);
    drop(dummy);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_icmp_error_egress() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}ic"), format!("natp{pid}ic"));
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;

    let share_pin = pin_root("icmperr");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();
    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();
    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();

    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        1,
        1,
        0,
        [192, 168, 1, 200],
        [203, 0, 113, 1],
        0,
        1,
    );
    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        0,
        1,
        0,
        [203, 0, 113, 1],
        [192, 168, 1, 200],
        0,
        1,
    );

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    let pkt = build_icmp_error_pkt(
        [192, 168, 1, 200],
        [10, 0, 0, 1],
        [192, 168, 1, 200],
        [10, 0, 0, 1],
        12345,
        80,
        3,
        0,
    );
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        1,
        1,
        0,
        [192, 168, 1, 200],
        [203, 0, 113, 1],
        0,
    );
    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        1,
        0,
        [203, 0, 113, 1],
        [192, 168, 1, 200],
        0,
    );

    drop(nat);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_static_ingress_mark() {
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nath{pid}sm"), format!("natp{pid}sm"));
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));
    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;

    let share_pin = pin_root("nat4mark");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();
    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();
    let _l0 = nat.progs.ingress_nat.attach_xdp(nat_h_i as i32).unwrap();

    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
        1,
    );

    let pkt = build_tcp_pkt([10, 0, 0, 1], [203, 0, 113, 1], 9999, 8080);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
    );

    drop(nat);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}

#[test]
fn xdp_nat_chain_pipeline() {
    let _lock = XDP_NAT_LOCK.lock().unwrap();
    let pid = crate::tests::test_id();
    let (nat_h, nat_p) = (format!("nch{pid}"), format!("ncp{pid}"));

    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
    Command::new("ip")
        .args(["link", "add", &nat_h, "type", "veth", "peer", "name", &nat_p])
        .output()
        .unwrap();
    Command::new("ip").args(["link", "set", nat_h.as_str(), "up"]).output().unwrap();
    Command::new("ip").args(["link", "set", nat_p.as_str(), "up"]).output().unwrap();
    thread::sleep(Duration::from_millis(100));

    let nat_h_i = if_nametoindex(nat_h.as_str()).unwrap() as u32;
    let nat_p_i = if_nametoindex(nat_p.as_str()).unwrap() as u32;

    let share_pin = pin_root("chain_pipe");
    let mut sb = ShareMapSkelBuilder::default();
    sb.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut share_obj = std::mem::MaybeUninit::uninit();
    let share = sb.open(&mut share_obj).unwrap().load().unwrap();

    let chain_b = XdpLanChainSkelBuilder::default();
    let mut chain_obj = std::mem::MaybeUninit::uninit();
    let chain = chain_b.open(&mut chain_obj).unwrap().load().unwrap();

    let mut nat_b = XdpNatSkelBuilder::default();
    nat_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut nat_obj = std::mem::MaybeUninit::uninit();
    let mut nat_open = nat_b.open(&mut nat_obj).unwrap();
    nat_open.maps.rodata_data.as_deref_mut().unwrap().current_ifindex = nat_h_i;
    let nat = nat_open.load().unwrap();

    let mut fw_b = XdpFirewallSkelBuilder::default();
    fw_b.object_builder_mut().pin_root_path(&share_pin).unwrap();
    let mut fw_obj = std::mem::MaybeUninit::uninit();
    let fw = fw_b.open(&mut fw_obj).unwrap().load().unwrap();

    let d_b = TestXdpDummySkelBuilder::default();
    let mut d_obj = std::mem::MaybeUninit::uninit();
    let dummy = d_b.open(&mut d_obj).unwrap().load().unwrap();

    let _l0 = nat.progs.egress_nat.attach_xdp(nat_h_i as i32).unwrap();
    let _l1 = dummy.progs.xdp_test_dummy.attach_xdp(nat_p_i as i32).unwrap();

    let dummy_fd = dummy.progs.xdp_test_dummy.as_fd().as_raw_fd();
    let fw_lan_fd = fw.progs.xdp_firewall_lan.as_fd().as_raw_fd();

    nat.maps
        .next_stage
        .update(&0u32.to_ne_bytes(), &fw_lan_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps.next_stage.update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY).unwrap();
    nat.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();
    fw.maps
        .xdp_pipe_exits_lan
        .update(&0u32.to_ne_bytes(), &dummy_fd.to_ne_bytes(), MapFlags::ANY)
        .unwrap();

    let mut wan_key = [0u8; 8];
    wan_key[0..4].copy_from_slice(&nat_h_i.to_ne_bytes());
    let mut wan_val = [0u8; 48];
    wan_val[0..4].copy_from_slice(&[203, 0, 113, 1]);
    share.maps.wan_ip_binding.update(&wan_key, &wan_val, MapFlags::ANY).unwrap();

    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
        1,
    );
    write_static_mapping_v4(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
        1,
    );

    let pkt = build_tcp_pkt([192, 168, 1, 100], [10, 0, 0, 1], 80, 9999);
    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
    );
    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
    );

    let block_action = 1u32.to_le_bytes();
    let mut fw_key = [0u8; 8];
    fw_key[0..4].copy_from_slice(&32u32.to_le_bytes());
    fw_key[4..8].copy_from_slice(&[203, 0, 113, 1]);
    fw.maps.firewall_block_ip4_map.update(&fw_key, &block_action, MapFlags::ANY).unwrap();

    for _ in 0..2 {
        send_raw_packet(&nat_p, &pkt);
        thread::sleep(Duration::from_millis(30));
    }
    thread::sleep(Duration::from_millis(500));

    assert_static_map_entry(
        &share.maps.nat4_st_map,
        1,
        6,
        80,
        [192, 168, 1, 100],
        [203, 0, 113, 1],
        8080,
    );
    assert_static_map_entry(
        &share.maps.nat4_st_map,
        0,
        6,
        8080,
        [203, 0, 113, 1],
        [192, 168, 1, 100],
        80,
    );
    let block_val = fw
        .maps
        .firewall_block_ip4_map
        .lookup(&fw_key, MapFlags::ANY)
        .expect("lookup block")
        .expect("block entry should exist");
    assert_eq!(&block_val[0..4], &block_action, "block action should be set");

    drop(fw);
    drop(nat);
    drop(dummy);
    drop(chain);
    drop(share);
    let _ = Command::new("ip").args(["link", "del", &nat_h]).output();
}
