use std::fmt::Debug;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use etherparse::PacketBuilder;

use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::tests::test_scanner::types::packet_info;
use crate::tests::test_scanner::types::u_inet_addr;

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
mod xdp_lan_route_test;
mod xdp_mss_clamp_test;
mod xdp_wan_route_test;

pub(crate) mod test_scanner {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_scanner.skel.rs"));
}

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

pub(crate) mod test_xdp_redirect {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_redirect.skel.rs"));
}

pub(crate) mod test_xdp_dummy {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/test_xdp_dummy.skel.rs"));
}

pub(crate) mod xdp_mss_clamp_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_mss_clamp.skel.rs"));
}

pub(crate) mod xdp_wan_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_wan_route.skel.rs"));
}

pub(crate) mod xdp_lan_route_skel {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf_rs/xdp_lan_route.skel.rs"));
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

unsafe impl plain::Plain for packet_info {}

impl u_inet_addr {
    pub fn to_string_with_proto(&self, l3_protocol: u8) -> String {
        unsafe {
            match l3_protocol {
                0 => {
                    let ip = Ipv4Addr::from(self.ip.to_be());
                    ip.to_string()
                }
                1 => {
                    let mut bytes = [0u8; 16];
                    for i in 0..4 {
                        bytes[i * 4..(i + 1) * 4].copy_from_slice(&self.ip6[i].to_be_bytes());
                    }
                    Ipv6Addr::from(bytes).to_string()
                }
                _ => "unknown".into(),
            }
        }
    }
}

impl std::fmt::Display for packet_info {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offset = &self.offset;
        let proto = offset.l3_protocol;

        writeln!(
            f,
            "Packet Info:\n\
            Status: {}\n\
            Packet Type: {}\n\
            L3 Protocol: {} | L4 Protocol: {}\n\
            Fragment Type: {} | Fragment ID: {} | Fragment Offset: {}\n\
            L3 Offset When Scan: {} | L4 Offset: {}\n\
            ICMP Error L3 Offset: {} | Inner L4 Offset: {}",
            offset.status,
            offset.pkt_type,
            offset.l3_protocol,
            offset.l4_protocol,
            offset.fragment_type,
            offset.fragment_id,
            offset.fragment_off,
            offset.l3_offset_when_scan,
            offset.l4_offset,
            offset.icmp_error_l3_offset,
            offset.icmp_error_inner_l4_offset,
        )?;

        writeln!(
            f,
            "IP Pair:\n  src: {}:{} -> dst: {}:{}",
            self.ip_pair.src_addr.to_string_with_proto(proto),
            self.ip_pair.src_port,
            self.ip_pair.dst_addr.to_string_with_proto(proto),
            self.ip_pair.dst_port
        )
    }
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
