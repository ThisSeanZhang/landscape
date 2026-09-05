//! `wan_ip_binding` map setting: associate WAN ifindex with IP/gateway/MAC
//! so the datapath can pick the correct egress interface and NPT prefix.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use landscape_common::net::MacAddr;
use libbpf_rs::{MapCore, MapFlags};
use zerocopy::IntoBytes;

use crate::maps::LandscapeMapPath;
use crate::{LANDSCAPE_IPV4_TYPE, LANDSCAPE_IPV6_TYPE};

use super::types::{WanIpInfoKey, WanIpInfoValue};
use crate::maps::Inet6Bytes;

pub fn add_ipv6_wan_ip(
    paths: &LandscapeMapPath,
    ifindex: u32,
    addr: Ipv6Addr,
    gateway: Option<Ipv6Addr>,
    mask: u8,
    mac: Option<MacAddr>,
) {
    let Ok(wan_ip_binding) = libbpf_rs::MapHandle::from_pinned_path(&paths.wan_ip) else {
        tracing::error!(
            "open pinned wan_ip_binding ({:?}) failed, skip ipv6 wan ip bind",
            paths.wan_ip
        );
        return;
    };
    add_wan_ip(&wan_ip_binding, ifindex, IpAddr::V6(addr), gateway.map(IpAddr::V6), mask, mac);
}

pub fn add_ipv4_wan_ip(
    paths: &LandscapeMapPath,
    ifindex: u32,
    addr: Ipv4Addr,
    gateway: Option<Ipv4Addr>,
    mask: u8,
    mac: Option<MacAddr>,
) {
    let Ok(wan_ip_binding) = libbpf_rs::MapHandle::from_pinned_path(&paths.wan_ip) else {
        tracing::error!(
            "open pinned wan_ip_binding ({:?}) failed, skip ipv4 wan ip bind",
            paths.wan_ip
        );
        return;
    };
    add_wan_ip(&wan_ip_binding, ifindex, IpAddr::V4(addr), gateway.map(IpAddr::V4), mask, mac);
}

/// Compute the NPT (Network Prefix Translation) mask for IPv6 prefix translation.
///
/// For a given prefix length N (0..64), the mask covers the bits between the
/// prefix and the 64-bit interface-ID boundary. These are the bits that should
/// be preserved from the LAN-side address during NPT translation.
///
/// The result is a little-endian u64 where each byte corresponds to bytes 0..7
/// of the IPv6 address (in network order). Bits *inside* the prefix are 0
/// (replaced by the WAN prefix) and bits *outside* the prefix (up to bit 63)
/// are 1 (kept from the LAN address).
fn compute_npt_mask(prefix_len: u8) -> u64 {
    if prefix_len >= 64 {
        return 0;
    }
    let mut mask: u64 = 0;
    let full_bytes = (prefix_len / 8) as usize;
    let remaining_bits = prefix_len % 8;
    for i in 0..8usize {
        let byte_mask: u8 = if i < full_bytes {
            0x00
        } else if i == full_bytes && remaining_bits > 0 {
            (1u8 << (8 - remaining_bits)) - 1
        } else {
            0xFF
        };
        mask |= (byte_mask as u64) << (i * 8);
    }
    mask
}

pub(crate) fn add_wan_ip<T>(
    wan_ip_binding: &T,
    ifindex: u32,
    addr: IpAddr,
    gateway: Option<IpAddr>,
    mask: u8,
    mac: Option<MacAddr>,
) where
    T: MapCore,
{
    tracing::debug!("add wan index - 1: {ifindex:?}");
    let mut key = WanIpInfoKey::default();
    let mut value = WanIpInfoValue::default();
    key.ifindex = ifindex;
    value.mask = mask;

    match addr {
        std::net::IpAddr::V4(ipv4_addr) => {
            value.addr.set_ipv4_be(ipv4_addr.to_bits());
            key.l3_protocol = LANDSCAPE_IPV4_TYPE;
        }
        std::net::IpAddr::V6(ipv6_addr) => {
            value.addr.set_ipv6(ipv6_addr);
            key.l3_protocol = LANDSCAPE_IPV6_TYPE;
            value.npt_mask = compute_npt_mask(mask);
        }
    };

    match gateway {
        Some(std::net::IpAddr::V4(ipv4_addr)) => {
            value.gateway.set_ipv4_be(ipv4_addr.to_bits());
        }
        Some(std::net::IpAddr::V6(ipv6_addr)) => {
            value.gateway.set_ipv6(ipv6_addr);
        }
        None => {}
    };

    match mac {
        Some(mac) => {
            value.mac = mac.octets();
            value.has_mac = 1;
        }
        None => {
            value.has_mac = 0;
        }
    }

    if let Err(e) = wan_ip_binding.update(key.as_bytes(), value.as_bytes(), MapFlags::ANY) {
        tracing::error!("setting wan ip error:{e:?}");
    } else {
        tracing::info!("setting wan index: {ifindex:?} addr:{addr:?}");
    }
}

pub fn del_ipv6_wan_ip(paths: &LandscapeMapPath, ifindex: u32) {
    del_wan_ip(paths, ifindex, LANDSCAPE_IPV6_TYPE);
}

pub fn del_ipv4_wan_ip(paths: &LandscapeMapPath, ifindex: u32) {
    del_wan_ip(paths, ifindex, LANDSCAPE_IPV4_TYPE);
}

#[allow(clippy::field_reassign_with_default)]
fn del_wan_ip(paths: &LandscapeMapPath, ifindex: u32, l3_protocol: u8) {
    tracing::debug!("del wan index - 1: {ifindex:?}");
    let Ok(wan_ip_binding) = libbpf_rs::MapHandle::from_pinned_path(&paths.wan_ip) else {
        tracing::error!(
            "open pinned wan_ip_binding ({:?}) failed, skip wan ip unbind",
            paths.wan_ip
        );
        return;
    };
    let mut key = WanIpInfoKey::default();
    key.ifindex = ifindex;
    key.l3_protocol = l3_protocol;

    if let Err(e) = wan_ip_binding.delete(key.as_bytes()) {
        tracing::error!("delete wan ip error:{e:?}");
    } else {
        tracing::info!("delete wan index: {ifindex:?}");
    }
}
