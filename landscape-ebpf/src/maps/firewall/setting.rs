//! Firewall blacklist maps (`firewall_block_ip4_map` / `firewall_block_ip6_map`):
//! sync IP/prefix blacklist entries from config in batch.

use std::{collections::HashSet, net::IpAddr};

use landscape_common::flow::ip_mark::IpConfig;
use libbpf_rs::{MapCore, MapFlags};
use zerocopy::IntoBytes;

use crate::maps::LandscapeMapPath;

use super::types::{FirewallAction, Ipv4LpmKey, Ipv6LpmKey};

pub fn sync_firewall_blacklist(
    paths: &LandscapeMapPath,
    new_ips: Vec<IpConfig>,
    old_ips: Vec<IpConfig>,
) {
    let new_set: HashSet<IpConfig> = new_ips.into_iter().collect();
    let old_set: HashSet<IpConfig> = old_ips.into_iter().collect();

    let to_add: Vec<&IpConfig> = new_set.difference(&old_set).collect();
    let to_del: Vec<&IpConfig> = old_set.difference(&new_set).collect();

    // Split into IPv4 and IPv6
    let (add_v4, add_v6): (Vec<&IpConfig>, Vec<&IpConfig>) =
        to_add.into_iter().partition(|ip| ip.ip.is_ipv4());
    let (del_v4, del_v6): (Vec<&IpConfig>, Vec<&IpConfig>) =
        to_del.into_iter().partition(|ip| ip.ip.is_ipv4());

    // IPv4 block map
    if !add_v4.is_empty() || !del_v4.is_empty() {
        match libbpf_rs::MapHandle::from_pinned_path(&paths.firewall_ipv4_block) {
            Ok(map) => {
                if !del_v4.is_empty() {
                    if let Err(e) = delete_blacklist_ipv4(&map, &del_v4) {
                        tracing::error!("del firewall blacklist ipv4: {e:?}");
                    }
                }
                if !add_v4.is_empty() {
                    if let Err(e) = add_blacklist_ipv4(&map, &add_v4) {
                        tracing::error!("add firewall blacklist ipv4: {e:?}");
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    "open pinned firewall_ipv4_block ({:?}) failed, skip ipv4 blacklist sync: {e}",
                    paths.firewall_ipv4_block
                );
            }
        }
    }

    // IPv6 block map
    if !add_v6.is_empty() || !del_v6.is_empty() {
        match libbpf_rs::MapHandle::from_pinned_path(&paths.firewall_ipv6_block) {
            Ok(map) => {
                if !del_v6.is_empty() {
                    if let Err(e) = delete_blacklist_ipv6(&map, &del_v6) {
                        tracing::error!("del firewall blacklist ipv6: {e:?}");
                    }
                }
                if !add_v6.is_empty() {
                    if let Err(e) = add_blacklist_ipv6(&map, &add_v6) {
                        tracing::error!("add firewall blacklist ipv6: {e:?}");
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    "open pinned firewall_ipv6_block ({:?}) failed, skip ipv6 blacklist sync: {e}",
                    paths.firewall_ipv6_block
                );
            }
        }
    }
}

fn add_blacklist_ipv4<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V4(addr) = ip.ip {
            let key = Ipv4LpmKey { prefixlen: ip.prefix, addr: addr.to_bits().to_be() };
            let value = FirewallAction { mark: 0 };
            keys.extend_from_slice(key.as_bytes());
            values.extend_from_slice(value.as_bytes());
        }
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

fn delete_blacklist_ipv4<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V4(addr) = ip.ip {
            let key = Ipv4LpmKey { prefixlen: ip.prefix, addr: addr.to_bits().to_be() };
            keys.extend_from_slice(key.as_bytes());
        }
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}

fn add_blacklist_ipv6<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let mut values = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V6(addr) = ip.ip {
            let mut key = Ipv6LpmKey { prefixlen: ip.prefix, addr: [0u8; 16] };
            key.addr.copy_from_slice(&addr.octets());
            let value = FirewallAction { mark: 0 };
            keys.extend_from_slice(key.as_bytes());
            values.extend_from_slice(value.as_bytes());
        }
    }

    map.update_batch(&keys, &values, count, MapFlags::ANY, MapFlags::ANY)
}

fn delete_blacklist_ipv6<T: MapCore>(map: &T, ips: &[&IpConfig]) -> libbpf_rs::Result<()> {
    if ips.is_empty() {
        return Ok(());
    }

    let mut keys = vec![];
    let count = ips.len() as u32;

    for ip in ips {
        if let IpAddr::V6(addr) = ip.ip {
            let mut key = Ipv6LpmKey { prefixlen: ip.prefix, addr: [0u8; 16] };
            key.addr.copy_from_slice(&addr.octets());
            keys.extend_from_slice(key.as_bytes());
        }
    }

    map.delete_batch(&keys, count, MapFlags::ANY, MapFlags::ANY)
}
