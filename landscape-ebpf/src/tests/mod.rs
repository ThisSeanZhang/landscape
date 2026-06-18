use std::fmt::Debug;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU32, Ordering};

use etherparse::PacketBuilder;

use zerocopy::FromBytes;
use zerocopy::IntoBytes;

static TEST_ID: AtomicU32 = AtomicU32::new(0);

pub(crate) fn test_id() -> u32 {
    TEST_ID.fetch_add(1, Ordering::Relaxed)
}

pub(crate) fn check_ifindex(name: &str, ifindex: u32) {
    const PIPELINE_COUNT: u32 = 1024;
    if ifindex >= PIPELINE_COUNT {
        eprintln!(
            "WARNING: {} ifindex {} >= PIPELINE_COUNT ({}) — pipe_root_progs or dispatching map lookups may fail",
            name, ifindex, PIPELINE_COUNT
        );
    }
}

#[allow(dead_code)]
pub(crate) fn checked_if_nametoindex(name: &str) -> u32 {
    let ifindex = nix::net::if_::if_nametoindex(name).expect(&format!("if_nametoindex({name})"));
    check_ifindex(name, ifindex as u32);
    ifindex as u32
}

mod check;
mod firewall;
mod mss;
mod nat;
mod pppoe;
mod route;
mod scanner;
mod time;
mod tproxy;
mod xdp_chain;
mod xdp_csum_verify;
mod xdp_firewall_test;
mod xdp_lan_intro_test;
mod xdp_mss_test;
mod xdp_nat_test;
mod xdp_wan_route_test;

pub(crate) mod test_firewall_packet {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_firewall_packet.skel.rs"));
}

pub(crate) mod test_route_packet {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_route_packet.skel.rs"));
}

pub(crate) mod test_tproxy_packet {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_tproxy_packet.skel.rs"));
}

pub(crate) mod test_xdp_root {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_root.skel.rs"));
}

pub(crate) mod test_xdp_chain_stage {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_chain_stage.skel.rs"));
}

pub(crate) mod test_xdp_dummy {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_dummy.skel.rs"));
}

pub(crate) mod xdp_mss_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_mss.skel.rs"));
}

pub(crate) mod xdp_wan_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_route.skel.rs"));
}

pub(crate) mod xdp_lan_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_intro.skel.rs"));
}

pub(crate) mod xdp_lan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_chain.skel.rs"));
}

pub(crate) mod xdp_wan_chain_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_chain.skel.rs"));
}

pub(crate) mod wan_intro_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_intro.skel.rs"));
}

pub(crate) mod test_xdp_scanner_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_scanner.skel.rs"));
}

pub(crate) mod xdp_firewall_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_firewall.skel.rs"));
}

pub(crate) mod xdp_nat_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_nat.skel.rs"));
}

pub(crate) mod test_csum_verify_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_csum_verify.skel.rs"));
}

#[repr(C, packed)]
#[derive(IntoBytes, FromBytes, Debug, Clone, Copy, Default)]
pub struct TestSkb {
    pub len: u32,
    pub pkt_type: u32,
    pub mark: u32,
    pub queue_mapping: u32,
    pub protocol: u32,
    pub vlan_present: u32,
    pub vlan_tci: u32,
    pub vlan_proto: u32,
    pub priority: u32,
    pub ingress_ifindex: u32,
    pub ifindex: u32,
    pub tc_index: u32,
    pub cb: [u32; 5],
    pub hash: u32,
    pub tc_classid: u32,
    pub data: u32,
    pub data_end: u32,
    pub napi_id: u32,
    pub family: u32,
    pub remote_ip4: u32,
    pub local_ip4: u32,
    pub remote_ip6: [u32; 4],
    pub local_ip6: [u32; 4],
    pub remote_port: u32,
    pub local_port: u32,
    pub data_meta: u32,
    pub flow_keys: u64,
    pub tstamp: u64,
    pub wire_len: u32,
    pub gso_segs: u32,
    pub sk: u64,
    pub gso_size: u32,
    pub tstamp_type: u8,
    pub _padding: [u8; 3],
    pub hwtstamp: u64,
}

fn dummpy_tcp_pkg() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], //source mac
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    ) //destination mac
    .ipv4(
        [192, 168, 1, 1], //source ip
        [192, 168, 1, 2], //destination ip
        64,               //time to life
    )
    .tcp(
        21, //source port
        1234, 12345, // sequence number
        4000,
    );

    let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

    let mut payload = Vec::<u8>::with_capacity(builder.size(tcp_payload.len()));
    builder.write(&mut payload, &tcp_payload).unwrap();

    payload
}

#[allow(dead_code)]
fn dummpy_ipv6_tcp_pkg() -> Vec<u8> {
    let builder = PacketBuilder::ethernet2(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], //source mac
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    ) //destination mac
    .ipv6(
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).octets(), //source ip
        Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc00a, 0x2ff).octets(), //destination ip
        64,                                                           //time to life
    )
    .tcp(
        21, //source port
        1234, 12345, // sequence number
        4000,
    );

    let tcp_payload = [1, 2, 3, 4, 5, 6, 7, 8];

    let mut payload = Vec::<u8>::with_capacity(builder.size(tcp_payload.len()));
    builder.write(&mut payload, &tcp_payload).unwrap();

    payload
}
