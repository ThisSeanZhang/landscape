//! `rt4`/`rt6_lan_map`, `rt4`/`rt6_cache_map`, `rt4`/`rt6_slot_map`
//! C anchor: real program skels.

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route4LanKey {
    pub prefixlen: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route6LanKey {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

/// `has_mac` is `_Bool` on the C side; it only appears on the encode path,
/// so only `IntoBytes` is derived.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route4LanInfo {
    pub has_mac: bool,
    pub mac_addr: [u8; 6],
    pub route_type: u8,
    pub ifindex: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route6LanInfo {
    pub has_mac: bool,
    pub mac_addr: [u8; 6],
    pub route_type: u8,
    pub ifindex: u32,
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route4CacheKey {
    pub local_addr: u32,
    pub remote_addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route6CacheKey {
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route4CacheValue {
    pub mark_value: u32,
    pub has_mac: u8,
    pub is_docker: u8,
    pub xdp_redirect_able: u8,
    pub _pad: u8,
    pub ifindex: u32,
    pub gate_addr: u32,
    pub mac: [u8; 6],
    pub l2_data: [u8; 8],
    pub _pad_tail: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route6CacheValue {
    pub mark_value: u32,
    pub has_mac: u8,
    pub is_docker: u8,
    pub xdp_redirect_able: u8,
    pub _pad: u8,
    pub ifindex: u32,
    pub gate_addr: [u8; 16],
    pub mac: [u8; 6],
    pub _pad_tail: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route4SlotKey {
    pub flow_id: u32,
    pub slot: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route6SlotKey {
    pub flow_id: u32,
    pub slot: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route4TargetInfo {
    pub ifindex: u32,
    pub gate_addr: u32,
    pub has_mac: u8,
    pub is_docker: u8,
    pub mac: [u8; 6],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Route6TargetInfo {
    pub ifindex: u32,
    pub gate_addr: [u8; 16],
    pub has_mac: u8,
    pub is_docker: u8,
    pub mac: [u8; 6],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xdp_wan_route::xdp_wan_route_skel::types as share;

    #[test]
    fn route_layouts_match_skel() {
        assert_size!(Route4LanKey, share::route4_lan_key);
        assert_field!(Route4LanKey, share::route4_lan_key, prefixlen);
        assert_field!(Route4LanKey, share::route4_lan_key, addr);

        assert_size!(Route6LanKey, share::route6_lan_key);
        assert_field!(Route6LanKey, share::route6_lan_key, prefixlen);
        assert_field!(Route6LanKey, share::route6_lan_key, addr);

        assert_size!(Route4LanInfo, share::route4_lan_info);
        assert_field!(Route4LanInfo, share::route4_lan_info, has_mac);
        assert_field!(Route4LanInfo, share::route4_lan_info, mac_addr);
        assert_field!(Route4LanInfo, share::route4_lan_info, route_type);
        assert_field!(Route4LanInfo, share::route4_lan_info, ifindex);
        assert_field!(Route4LanInfo, share::route4_lan_info, addr);

        assert_size!(Route6LanInfo, share::route6_lan_info);
        assert_field!(Route6LanInfo, share::route6_lan_info, has_mac);
        assert_field!(Route6LanInfo, share::route6_lan_info, mac_addr);
        assert_field!(Route6LanInfo, share::route6_lan_info, route_type);
        assert_field!(Route6LanInfo, share::route6_lan_info, ifindex);
        assert_field!(Route6LanInfo, share::route6_lan_info, addr);

        assert_size!(Route4CacheKey, share::route4_cache_key);
        assert_field!(Route4CacheKey, share::route4_cache_key, local_addr);
        assert_field!(Route4CacheKey, share::route4_cache_key, remote_addr);

        assert_size!(Route6CacheKey, share::route6_cache_key);
        assert_field!(Route6CacheKey, share::route6_cache_key, local_addr);
        assert_field!(Route6CacheKey, share::route6_cache_key, remote_addr);

        assert_size!(Route4CacheValue, share::route4_cache_value);
        assert_field!(Route4CacheValue, share::route4_cache_value, mark_value);
        assert_field!(Route4CacheValue, share::route4_cache_value, has_mac);
        assert_field!(Route4CacheValue, share::route4_cache_value, is_docker);
        assert_field!(Route4CacheValue, share::route4_cache_value, xdp_redirect_able);
        assert_field!(Route4CacheValue, share::route4_cache_value, ifindex);
        assert_field!(Route4CacheValue, share::route4_cache_value, gate_addr);
        assert_field!(Route4CacheValue, share::route4_cache_value, mac);
        assert_field!(Route4CacheValue, share::route4_cache_value, l2_data);

        assert_size!(Route6CacheValue, share::route6_cache_value);
        assert_field!(Route6CacheValue, share::route6_cache_value, mark_value);
        assert_field!(Route6CacheValue, share::route6_cache_value, has_mac);
        assert_field!(Route6CacheValue, share::route6_cache_value, is_docker);
        assert_field!(Route6CacheValue, share::route6_cache_value, xdp_redirect_able);
        assert_field!(Route6CacheValue, share::route6_cache_value, ifindex);
        assert_field!(Route6CacheValue, share::route6_cache_value, gate_addr);
        assert_field!(Route6CacheValue, share::route6_cache_value, mac);

        assert_size!(Route4SlotKey, share::route4_slot_key);
        assert_field!(Route4SlotKey, share::route4_slot_key, flow_id);
        assert_field!(Route4SlotKey, share::route4_slot_key, slot);

        assert_size!(Route6SlotKey, share::route6_slot_key);
        assert_field!(Route6SlotKey, share::route6_slot_key, flow_id);
        assert_field!(Route6SlotKey, share::route6_slot_key, slot);

        assert_size!(Route4TargetInfo, share::route4_target_info);
        assert_field!(Route4TargetInfo, share::route4_target_info, ifindex);
        assert_field!(Route4TargetInfo, share::route4_target_info, gate_addr);
        assert_field!(Route4TargetInfo, share::route4_target_info, has_mac);
        assert_field!(Route4TargetInfo, share::route4_target_info, is_docker);
        assert_field!(Route4TargetInfo, share::route4_target_info, mac);

        assert_size!(Route6TargetInfo, share::route6_target_info);
        assert_field!(Route6TargetInfo, share::route6_target_info, ifindex);
        assert_field!(Route6TargetInfo, share::route6_target_info, gate_addr);
        assert_field!(Route6TargetInfo, share::route6_target_info, has_mac);
        assert_field!(Route6TargetInfo, share::route6_target_info, is_docker);
        assert_field!(Route6TargetInfo, share::route6_target_info, mac);
    }
}
