//! `rt4`/`rt6_lan_map`, `rt4`/`rt6_cache_map`, `rt4`/`rt6_target_slot_map`
//! (see `share_map.skel.rs`).

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct LanRouteKeyV4 {
    pub prefixlen: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct LanRouteKeyV6 {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

/// `has_mac` is `_Bool` on the C side; it only appears on the encode path,
/// so only `IntoBytes` is derived.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct LanRouteInfoV4 {
    pub has_mac: bool,
    pub mac_addr: [u8; 6],
    pub route_type: u8,
    pub ifindex: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct LanRouteInfoV6 {
    pub has_mac: bool,
    pub mac_addr: [u8; 6],
    pub route_type: u8,
    pub ifindex: u32,
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RtCacheKeyV4 {
    pub local_addr: u32,
    pub remote_addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RtCacheKeyV6 {
    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RtCacheValueV4 {
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
pub(crate) struct RtCacheValueV6 {
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
pub(crate) struct RouteTargetSlotKeyV4 {
    pub flow_id: u32,
    pub slot: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteTargetSlotKeyV6 {
    pub flow_id: u32,
    pub slot: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteTargetInfoV4 {
    pub ifindex: u32,
    pub gate_addr: u32,
    pub has_mac: u8,
    pub is_docker: u8,
    pub mac: [u8; 6],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteTargetInfoV6 {
    pub ifindex: u32,
    pub gate_addr: [u8; 16],
    pub has_mac: u8,
    pub is_docker: u8,
    pub mac: [u8; 6],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::share_map::types as share;

    #[test]
    fn route_layouts_match_skel() {
        assert_size!(LanRouteKeyV4, share::lan_route_key_v4);
        assert_field!(LanRouteKeyV4, share::lan_route_key_v4, prefixlen);
        assert_field!(LanRouteKeyV4, share::lan_route_key_v4, addr);

        assert_size!(LanRouteKeyV6, share::lan_route_key_v6);
        assert_field!(LanRouteKeyV6, share::lan_route_key_v6, prefixlen);
        assert_field!(LanRouteKeyV6, share::lan_route_key_v6, addr);

        assert_size!(LanRouteInfoV4, share::lan_route_info_v4);
        assert_field!(LanRouteInfoV4, share::lan_route_info_v4, has_mac);
        assert_field!(LanRouteInfoV4, share::lan_route_info_v4, mac_addr);
        assert_field!(LanRouteInfoV4, share::lan_route_info_v4, route_type);
        assert_field!(LanRouteInfoV4, share::lan_route_info_v4, ifindex);
        assert_field!(LanRouteInfoV4, share::lan_route_info_v4, addr);

        assert_size!(LanRouteInfoV6, share::lan_route_info_v6);
        assert_field!(LanRouteInfoV6, share::lan_route_info_v6, has_mac);
        assert_field!(LanRouteInfoV6, share::lan_route_info_v6, mac_addr);
        assert_field!(LanRouteInfoV6, share::lan_route_info_v6, route_type);
        assert_field!(LanRouteInfoV6, share::lan_route_info_v6, ifindex);
        assert_field!(LanRouteInfoV6, share::lan_route_info_v6, addr);

        assert_size!(RtCacheKeyV4, share::rt_cache_key_v4);
        assert_field!(RtCacheKeyV4, share::rt_cache_key_v4, local_addr);
        assert_field!(RtCacheKeyV4, share::rt_cache_key_v4, remote_addr);

        assert_size!(RtCacheKeyV6, share::rt_cache_key_v6);
        assert_field!(RtCacheKeyV6, share::rt_cache_key_v6, local_addr);
        assert_field!(RtCacheKeyV6, share::rt_cache_key_v6, remote_addr);

        assert_size!(RtCacheValueV4, share::rt_cache_value_v4);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, mark_value);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, has_mac);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, is_docker);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, xdp_redirect_able);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, ifindex);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, gate_addr);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, mac);
        assert_field!(RtCacheValueV4, share::rt_cache_value_v4, l2_data);

        assert_size!(RtCacheValueV6, share::rt_cache_value_v6);
        assert_field!(RtCacheValueV6, share::rt_cache_value_v6, mark_value);
        assert_field!(RtCacheValueV6, share::rt_cache_value_v6, has_mac);
        assert_field!(RtCacheValueV6, share::rt_cache_value_v6, is_docker);
        assert_field!(RtCacheValueV6, share::rt_cache_value_v6, xdp_redirect_able);
        assert_field!(RtCacheValueV6, share::rt_cache_value_v6, ifindex);
        assert_field!(RtCacheValueV6, share::rt_cache_value_v6, gate_addr);
        assert_field!(RtCacheValueV6, share::rt_cache_value_v6, mac);

        assert_size!(RouteTargetSlotKeyV4, share::route_target_slot_key_v4);
        assert_field!(RouteTargetSlotKeyV4, share::route_target_slot_key_v4, flow_id);
        assert_field!(RouteTargetSlotKeyV4, share::route_target_slot_key_v4, slot);

        assert_size!(RouteTargetSlotKeyV6, share::route_target_slot_key_v6);
        assert_field!(RouteTargetSlotKeyV6, share::route_target_slot_key_v6, flow_id);
        assert_field!(RouteTargetSlotKeyV6, share::route_target_slot_key_v6, slot);

        assert_size!(RouteTargetInfoV4, share::route_target_info_v4);
        assert_field!(RouteTargetInfoV4, share::route_target_info_v4, ifindex);
        assert_field!(RouteTargetInfoV4, share::route_target_info_v4, gate_addr);
        assert_field!(RouteTargetInfoV4, share::route_target_info_v4, has_mac);
        assert_field!(RouteTargetInfoV4, share::route_target_info_v4, is_docker);
        assert_field!(RouteTargetInfoV4, share::route_target_info_v4, mac);

        assert_size!(RouteTargetInfoV6, share::route_target_info_v6);
        assert_field!(RouteTargetInfoV6, share::route_target_info_v6, ifindex);
        assert_field!(RouteTargetInfoV6, share::route_target_info_v6, gate_addr);
        assert_field!(RouteTargetInfoV6, share::route_target_info_v6, has_mac);
        assert_field!(RouteTargetInfoV6, share::route_target_info_v6, is_docker);
        assert_field!(RouteTargetInfoV6, share::route_target_info_v6, mac);
    }
}
