//! Off-link Ethernet fixtures. Keep ingress, neighbour and confirmed headers distinct.
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

use landscape_common::net::MacAddr;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use zerocopy::{FromBytes, IntoBytes};

use super::{lookup_inner_map, route_slot, route_slot_v6, simple_ipv4_tcp, simple_ipv6_tcp_syn};
use crate::maps::{
    Route4CacheKey, Route4CacheValue, Route4SlotKey, Route4TargetInfo, Route6CacheKey,
    Route6CacheValue, Route6SlotKey, Route6TargetInfo,
    route::cache::{LAN_CACHE, WAN_CACHE},
};
use crate::tests::helper::map::{insert_ip_mac_v4, insert_ip_mac_v6};

pub(super) const WAN4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
pub(super) const GW4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub(super) const GW6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
pub(super) const NEIGH_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x11];
pub(super) const NEIGH_DEV_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x12];
pub(super) const CONFIRMED_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x21];
pub(super) const WAN_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x22];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Family {
    V4,
    V6,
}

pub(super) struct RouteCase {
    family: Family,
    pub(super) packet: Vec<u8>,
    cache: MapHandle,
    reverse_cache: MapHandle,
    cache_key: Vec<u8>,
    slots: MapHandle,
    slot_key: Vec<u8>,
}
impl RouteCase {
    pub(super) fn cached_ifindex(&self) -> Option<u32> {
        self.cache.lookup(&self.cache_key, MapFlags::ANY).unwrap().map(|bytes| match self.family {
            Family::V4 => Route4CacheValue::read_from_bytes(&bytes).unwrap().ifindex,
            Family::V6 => Route6CacheValue::read_from_bytes(&bytes).unwrap().ifindex,
        })
    }

    pub(super) fn clear_cache(&self) {
        self.cache.delete(&self.cache_key).unwrap();
    }

    /// Reuse the same target and address pair, but leave only the reverse path in the map.
    pub(super) fn use_reverse_cache(&self) {
        let target = self.cache.lookup(&self.cache_key, MapFlags::ANY).unwrap().unwrap();
        self.reverse_cache.update(&self.cache_key, &target, MapFlags::ANY).unwrap();
        self.clear_cache();
    }

    /// After removing the slot, only a cache hit can reach the WAN root.
    pub(super) fn remove_slot(&self) {
        self.slots.delete(&self.slot_key).unwrap();
    }
}

/// These neighbour maps aren't pinned by name; the production loader explicitly reuses them.
pub(super) fn reuse_route_neighbours(
    open: &mut crate::skel::xdp_lan_route::OpenXdpLanRouteSkel<'_>,
    pin: &Path,
) {
    let paths = crate::LandscapeMapPath::from_root(pin);
    crate::landscape::pin_and_reuse_map(&mut open.maps.ip_mac_v4, &paths.ip_mac_v4).unwrap();
    crate::landscape::pin_and_reuse_map(&mut open.maps.ip_mac_v6, &paths.ip_mac_v6).unwrap();
}

pub(super) fn seed_route(
    pin: &Path,
    family: Family,
    ifindex: u32,
    link_chain_id: u16,
) -> RouteCase {
    let maps = crate::tests::init_shared_maps_for_test(pin);
    let paths = crate::LandscapeMapPath::from_root(pin);
    let neigh = MacAddr::from(NEIGH_MAC);
    let dev = MacAddr::from(NEIGH_DEV_MAC);
    match family {
        Family::V4 => {
            let src = Ipv4Addr::new(10, 0, 0, 1);
            let dst = Ipv4Addr::new(203, 0, 113, 9);
            let slot = Route4SlotKey { flow_id: 0, slot: route_slot(dst.to_bits()) };
            let target = Route4TargetInfo {
                ifindex,
                link_chain_id,
                has_mac: 1,
                ..Default::default()
            };
            maps.rt4_slot_map.update(slot.as_bytes(), target.as_bytes(), MapFlags::ANY).unwrap();
            insert_ip_mac_v4(
                &MapHandle::from_pinned_path(&paths.ip_mac_v4).unwrap(),
                GW4,
                neigh,
                dev,
                ifindex,
            );
            let key = Route4CacheKey {
                local_addr: src.to_bits().to_be(),
                remote_addr: dst.to_bits().to_be(),
            };
            RouteCase {
                family,
                packet: simple_ipv4_tcp(src, dst),
                cache: lookup_inner_map(&maps.rt4_cache_map, LAN_CACHE),
                reverse_cache: lookup_inner_map(&maps.rt4_cache_map, WAN_CACHE),
                cache_key: key.as_bytes().to_vec(),
                slots: maps.rt4_slot_map,
                slot_key: slot.as_bytes().to_vec(),
            }
        }
        Family::V6 => {
            let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
            let dst = Ipv6Addr::new(0x2001, 0xdb8, 0x113, 0, 0, 0, 0, 9);
            let slot = Route6SlotKey { flow_id: 0, slot: route_slot_v6(&dst.octets()) };
            let target = Route6TargetInfo {
                ifindex,
                link_chain_id,
                has_mac: 1,
                ..Default::default()
            };
            maps.rt6_slot_map.update(slot.as_bytes(), target.as_bytes(), MapFlags::ANY).unwrap();
            insert_ip_mac_v6(
                &MapHandle::from_pinned_path(&paths.ip_mac_v6).unwrap(),
                GW6,
                neigh,
                dev,
                ifindex,
            );
            let key = Route6CacheKey {
                local_addr: src.octets(),
                remote_addr: dst.octets(),
            };
            RouteCase {
                family,
                packet: simple_ipv6_tcp_syn(src, dst),
                cache: lookup_inner_map(&maps.rt6_cache_map, LAN_CACHE),
                reverse_cache: lookup_inner_map(&maps.rt6_cache_map, WAN_CACHE),
                cache_key: key.as_bytes().to_vec(),
                slots: maps.rt6_slot_map,
                slot_key: slot.as_bytes().to_vec(),
            }
        }
    }
}
