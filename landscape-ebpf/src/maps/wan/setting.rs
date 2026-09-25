//! `wan_ip_binding` map setting: associate a logical chain id with its
//! WAN IP/gateway/MAC so the datapath can pick the correct egress metadata
//! and NPT prefix. Physical ifindex remains a redirect/device attribute.

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
    _ifindex: u32,
    link_chain_id: u16,
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
    add_wan_ip(
        &wan_ip_binding,
        link_chain_id as u32,
        IpAddr::V6(addr),
        gateway.map(IpAddr::V6),
        mask,
        mac,
    );
    register_dispatch_selector(paths, link_chain_id, IpAddr::V6(addr));
}

pub fn add_ipv4_wan_ip(
    paths: &LandscapeMapPath,
    _ifindex: u32,
    link_chain_id: u16,
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
    add_wan_ip(
        &wan_ip_binding,
        link_chain_id as u32,
        IpAddr::V4(addr),
        gateway.map(IpAddr::V4),
        mask,
        mac,
    );
    register_dispatch_selector(paths, link_chain_id, IpAddr::V4(addr));
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
    chain_id: u32,
    addr: IpAddr,
    gateway: Option<IpAddr>,
    mask: u8,
    mac: Option<MacAddr>,
) where
    T: MapCore,
{
    tracing::debug!("add wan chain id: {chain_id:?}");
    let mut key = WanIpInfoKey::default();
    let mut value = WanIpInfoValue::default();
    key.chain_id = chain_id;
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
        tracing::info!("setting wan chain id: {chain_id:?} addr:{addr:?}");
    }
}

pub fn del_ipv6_wan_ip(paths: &LandscapeMapPath, _ifindex: u32, link_chain_id: u16) {
    del_wan_ip(paths, link_chain_id, LANDSCAPE_IPV6_TYPE);
    remove_dispatch_selectors(paths, link_chain_id, LANDSCAPE_IPV6_TYPE);
}

pub fn del_ipv4_wan_ip(paths: &LandscapeMapPath, _ifindex: u32, link_chain_id: u16) {
    del_wan_ip(paths, link_chain_id, LANDSCAPE_IPV4_TYPE);
    remove_dispatch_selectors(paths, link_chain_id, LANDSCAPE_IPV4_TYPE);
}

fn dispatch_key(addr: IpAddr) -> [u8; 16] {
    let mut key = [0u8; 16];
    match addr {
        IpAddr::V4(ip) => {
            key[0] = LANDSCAPE_IPV4_TYPE;
            key[12..16].copy_from_slice(&ip.to_bits().to_be_bytes());
        }
        IpAddr::V6(ip) => {
            key[0] = LANDSCAPE_IPV6_TYPE;
            key[8..16].copy_from_slice(&ip.octets()[..8]);
        }
    }
    key
}

fn register_dispatch_selector(paths: &LandscapeMapPath, chain_id: u16, addr: IpAddr) {
    let key = dispatch_key(addr);
    let value = (chain_id as u32).to_ne_bytes();
    for path in [paths.xdp_wan_intro_dispatch_path(), paths.tc_wan_intro_dispatch_path()] {
        let Ok(map) = libbpf_rs::MapHandle::from_pinned_path(&path) else {
            continue;
        };
        if let Err(err) = map.update(&key, &value, MapFlags::ANY) {
            tracing::warn!("register WAN dispatch selector {} failed: {err}", path.display());
        }
    }
}

fn remove_dispatch_selectors(paths: &LandscapeMapPath, chain_id: u16, dispatch_type: u8) {
    let expected = (chain_id as u32).to_ne_bytes();
    for path in [paths.xdp_wan_intro_dispatch_path(), paths.tc_wan_intro_dispatch_path()] {
        let Ok(map) = libbpf_rs::MapHandle::from_pinned_path(&path) else {
            continue;
        };
        let keys: Vec<Vec<u8>> = map.keys().collect();
        for key in keys {
            if key.first().copied() == Some(dispatch_type) {
                if let Ok(Some(value)) = map.lookup(&key, MapFlags::ANY) {
                    if value.len() >= 4 && value[0..4] == expected {
                        let _ = map.delete(&key);
                    }
                }
            }
        }
    }
}

/// `wan_intro_dispatch_map` selector type for PPPoE session ids.  Mirrors
/// `WAN_INTRO_PPP_SESSION_TYPE` in bpf/landscape.h.
const WAN_INTRO_PPP_SESSION_TYPE: u8 = 3;

/// PPPoE session-scoped dispatch key.  Must byte-match `struct dispatch_ppp`
/// in bpf/xdp_wan_intro.bpf.c: little-endian u32 dispatch type at 0..4, then
/// the session id as a big-endian u32 (high 16 bits zero) at 12..16 — the
/// same encoding the C side builds with `bpf_htonl((__u32)bpf_ntohs(sid))`.
fn ppp_session_dispatch_key(session_id: u16) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0] = WAN_INTRO_PPP_SESSION_TYPE;
    key[12..16].copy_from_slice(&(u32::from(session_id)).to_be_bytes());
    key
}

/// Map a PPPoE session id to its logical chain in both pinned dispatch maps,
/// so the WAN intro can pick the correct chain for inbound session frames
/// when several sessions share one attach iface.
pub fn register_ppp_session_selector(paths: &LandscapeMapPath, chain_id: u16, session_id: u16) {
    let key = ppp_session_dispatch_key(session_id);
    let value = (chain_id as u32).to_ne_bytes();
    for path in [paths.xdp_wan_intro_dispatch_path(), paths.tc_wan_intro_dispatch_path()] {
        let Ok(map) = libbpf_rs::MapHandle::from_pinned_path(&path) else {
            continue;
        };
        if let Err(err) = map.update(&key, &value, MapFlags::ANY) {
            tracing::warn!("register PPP session selector {} failed: {err}", path.display());
        }
    }
}

/// Drop the session selector again, but only if it still points at `chain_id`.
pub fn remove_ppp_session_selector(paths: &LandscapeMapPath, chain_id: u16, session_id: u16) {
    let key = ppp_session_dispatch_key(session_id);
    let expected = (chain_id as u32).to_ne_bytes();
    for path in [paths.xdp_wan_intro_dispatch_path(), paths.tc_wan_intro_dispatch_path()] {
        let Ok(map) = libbpf_rs::MapHandle::from_pinned_path(&path) else {
            continue;
        };
        if let Ok(Some(value)) = map.lookup(&key, MapFlags::ANY) {
            if value.len() >= 4 && value[0..4] == expected {
                let _ = map.delete(&key);
            }
        }
    }
}

#[allow(clippy::field_reassign_with_default)]
fn del_wan_ip(paths: &LandscapeMapPath, chain_id: u16, l3_protocol: u8) {
    tracing::debug!("del wan chain id: {chain_id:?}");
    let Ok(wan_ip_binding) = libbpf_rs::MapHandle::from_pinned_path(&paths.wan_ip) else {
        tracing::error!(
            "open pinned wan_ip_binding ({:?}) failed, skip wan ip unbind",
            paths.wan_ip
        );
        return;
    };
    let mut key = WanIpInfoKey::default();
    key.chain_id = chain_id as u32;
    key.l3_protocol = l3_protocol;

    if let Err(e) = wan_ip_binding.delete(key.as_bytes()) {
        tracing::error!("delete wan ip error:{e:?}");
    } else {
        tracing::info!("delete wan chain id: {chain_id:?}");
    }
}

#[cfg(test)]
mod ppp_session_tests {
    use super::ppp_session_dispatch_key;

    #[test]
    fn key_layout_matches_c_dispatch_ppp() {
        let key = ppp_session_dispatch_key(0x1234);
        // little-endian u32 dispatch type
        assert_eq!(&key[0..4], &[3, 0, 0, 0]);
        // big-endian u32 session id, high half zero
        assert_eq!(&key[4..12], &[0u8; 8]);
        assert_eq!(&key[12..16], &[0x00, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn key_layout_max_session() {
        let key = ppp_session_dispatch_key(0xffff);
        assert_eq!(&key[12..16], &[0x00, 0x00, 0xff, 0xff]);
    }
}
