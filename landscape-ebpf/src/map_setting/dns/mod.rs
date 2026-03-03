use libbpf_rs::{MapCore, MapFlags};

use crate::MAP_PATHS;

const DNS_FLOW_PROTO_UDP: u8 = 17;
const DNS_FLOW_PROTO_TCP: u8 = 6;

#[inline]
fn dns_flow_key(flow_id: u32, proto: u8) -> u32 {
    let proto_bit = if proto == DNS_FLOW_PROTO_TCP { 1 } else { 0 };
    (flow_id << 1) | proto_bit
}

fn setting_dns_sock_map_inner(sock_fd: i32, flow_id: u32, proto: u8) {
    let dns_flow_socks = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.dns_flow_socks).unwrap();

    let key = dns_flow_key(flow_id, proto).to_le_bytes();
    let value = (sock_fd as u64).to_le_bytes();
    if let Err(e) = dns_flow_socks.update(&key, &value, MapFlags::ANY) {
        tracing::error!("update dns_flow_socks error: {e:?}");
    }
}

pub fn setting_dns_sock_map(sock_fd: i32, flow_id: u32) {
    setting_dns_sock_map_inner(sock_fd, flow_id, DNS_FLOW_PROTO_UDP);
}

pub fn setting_dns_sock_map_tcp(sock_fd: i32, flow_id: u32) {
    setting_dns_sock_map_inner(sock_fd, flow_id, DNS_FLOW_PROTO_TCP);
}

fn del_dns_sock_map_inner(flow_id: u32, proto: u8) {
    let dns_flow_socks = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.dns_flow_socks).unwrap();

    let key = dns_flow_key(flow_id, proto).to_le_bytes();

    if let Err(e) = dns_flow_socks.delete(&key) {
        tracing::error!("del dns_flow_socks error: {e:?}");
    }
}

pub fn del_dns_sock_map(flow_id: u32) {
    del_dns_sock_map_inner(flow_id, DNS_FLOW_PROTO_UDP);
}

pub fn del_dns_sock_map_tcp(flow_id: u32) {
    del_dns_sock_map_inner(flow_id, DNS_FLOW_PROTO_TCP);
}
