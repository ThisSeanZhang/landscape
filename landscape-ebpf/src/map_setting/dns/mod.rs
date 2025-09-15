use libbpf_rs::{MapCore, MapFlags};

use crate::MAP_PATHS;

pub fn setting_dns_sock_map(sock_fd: i32, flow_id: u32) {
    let dns_flow_socks = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.dns_flow_socks).unwrap();

    let key = flow_id.to_le_bytes();
    let value = (sock_fd as u64).to_le_bytes();

    if let Err(e) = dns_flow_socks.update(&key, &value, MapFlags::ANY) {
        tracing::error!("update dns_flow_socks error: {e:?}");
    }
}

pub fn del_dns_sock_map(flow_id: u32) {
    let dns_flow_socks = libbpf_rs::MapHandle::from_pinned_path(&MAP_PATHS.dns_flow_socks).unwrap();

    let key = flow_id.to_le_bytes();

    if let Err(e) = dns_flow_socks.delete(&key) {
        tracing::error!("del dns_flow_socks error: {e:?}");
    }
}
