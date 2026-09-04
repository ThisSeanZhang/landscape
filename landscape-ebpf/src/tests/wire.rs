//! Mirror types for test-only eBPF output snapshots (result map values of
//! test_skb_scanner / test_xdp_scanner / test_skb_read / test_tproxy_packet /
//! test_route_packet).
//!
//! Same conventions as `crate::map_types`: layouts are pinned by layout
//! consistency tests; C unions (`u_inet_addr` / `u_inet6_addr` / `in6_addr`) are modeled
//! as `[u8; 16]`; implicit padding is spelled out explicitly. These types are
//! decode-only, so only `FromBytes` is derived.

use zerocopy::{FromBytes, Immutable};

// =============================================================================
// Scanner sub-structs shared by test_skb_scanner / test_xdp_scanner /
// test_skb_read. The three skels define them identically; layout consistency
// tests check each skel separately.
// =============================================================================

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct ScanIpv4Idx {
    pub l4_offset: u16,
    pub fragment_off: u16,
    pub fragment_id: u16,
    pub l4_protocol: u8,
    pub fragment_type: u8,
    pub pkt_type: u8,
    pub _pad: [u8; 1],
    pub icmp_error_l3_offset: u16,
    pub icmp_error_inner_l4_offset: u16,
    pub icmp_error_l4_protocol: u8,
    pub _pad_tail: [u8; 1],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct ScanIpv6Idx {
    pub l4_offset: u16,
    pub fragment_off: u16,
    pub fragment_id: u32,
    pub l4_protocol: u8,
    pub fragment_type: u8,
    pub pkt_type: u8,
    pub _pad: [u8; 1],
    pub icmp_error_l3_offset: u16,
    pub icmp_error_inner_l4_offset: u16,
    pub icmp_error_l4_protocol: u8,
    pub _pad_tail: [u8; 3],
}

/// C side `skb_scan_test_result` / `xdp_scan_test_result` (both skels define
/// them identically).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct SkbScanResult {
    pub scan_ret: u8,
    pub l3_proto: u8,
    pub _pad: [u8; 2],
    pub v4: ScanIpv4Idx,
    pub v6: ScanIpv6Idx,
}

/// C side `skb_icmp_test_result`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct SkbIcmpTestResult {
    pub scan_ret: u8,
    pub l3_proto: u8,
    pub _pad: [u8; 2],
    pub icmp_error_l3_offset: u16,
    pub icmp_error_inner_l4_offset: u16,
    pub icmp_error_l4_protocol: u8,
    pub pkt_type: u8,
    pub _pad0: [u8; 2],
    pub v4_saddr: u32,
    pub v6_saddr: [u8; 16],
}

/// C side `inet4_pair` (test_skb_read).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Inet4Pair {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// C side `inet_pair` (union-address flavor, test_skb_read /
/// test_tproxy_packet).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct InetPair {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

/// C side `skb_read_test_result`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct SkbReadTestResult {
    pub l3_proto: u8,
    pub _pad: [u8; 3],
    pub scan_ret: i32,
    pub read_l3_ret: i32,
    pub read_info_ret: i32,
    pub v4_idx: ScanIpv4Idx,
    pub v6_idx: ScanIpv6Idx,
    pub v4_l3_saddr: u32,
    pub v4_l3_daddr: u32,
    pub v6_l3_saddr: [u8; 16],
    pub v6_l3_daddr: [u8; 16],
    pub v4_info: Inet4Pair,
    pub v6_info: InetPair,
}

// =============================================================================
// tproxy / route packet (packet_offset_info is defined identically in both
// skels)
// =============================================================================

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct PacketOffsetInfo {
    pub icmp_error_l3_protocol: u8,
    pub icmp_error_l4_protocol: u8,
    pub status: u16,
    pub pkt_type: u8,
    pub l3_protocol: u8,
    pub l4_protocol: u8,
    pub fragment_type: u8,
    pub fragment_off: u16,
    pub fragment_id: u16,
    pub l4_offset: u16,
    pub l3_offset_when_scan: u16,
    pub icmp_error_l3_offset: u16,
    pub icmp_error_inner_l4_offset: u16,
}

/// C side `tproxy_packet_test_result`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct TproxyPacketTestResult {
    pub offset: PacketOffsetInfo,
    pub pair: InetPair,
    pub scan_ret: i32,
    pub read_ret: i32,
}

/// C side `route_context_v4`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteContextV4 {
    pub saddr: u32,
    pub daddr: u32,
    pub l4_protocol: u8,
    pub tos: u8,
    pub smac: [u8; 6],
}

/// C side `route_context_v6`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteContextV6 {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub l4_protocol: u8,
    pub tos: u8,
    pub smac: [u8; 6],
}

/// C side `route_packet_test_result`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RoutePacketTestResult {
    pub offset: PacketOffsetInfo,
    pub v4: RouteContextV4,
    pub v6: RouteContextV6,
    pub scan_ret: i32,
    pub read_ret: i32,
    pub forward_ret: i32,
}

#[cfg(test)]
mod tests {
    use crate::tests::wire::*;

    macro_rules! assert_size {
        ($mirror:ty, $skel:ty) => {
            assert_eq!(
                std::mem::size_of::<$mirror>(),
                std::mem::size_of::<$skel>(),
                concat!("size mismatch: ", stringify!($mirror), " vs ", stringify!($skel)),
            );
        };
    }

    macro_rules! assert_field {
        ($mirror:ty, $skel:ty, $($field:tt).+) => {
            assert_eq!(
                std::mem::offset_of!($mirror, $($field).+),
                std::mem::offset_of!($skel, $($field).+),
                concat!(
                    "offset mismatch: ",
                    stringify!($mirror),
                    ".",
                    stringify!($($field).+),
                ),
            );
        };
    }

    /// When field names differ (union modeling / nested flattening), specify
    /// the mirror and skel field paths separately.
    macro_rules! assert_field_as {
        ($mirror:ty, $($mfield:tt).+, $skel:ty, $($sfield:tt).+) => {
            assert_eq!(
                std::mem::offset_of!($mirror, $($mfield).+),
                std::mem::offset_of!($skel, $($sfield).+),
                concat!(
                    "offset mismatch: ",
                    stringify!($mirror),
                    ".",
                    stringify!($($mfield).+),
                    " vs ",
                    stringify!($skel),
                    ".",
                    stringify!($($sfield).+),
                ),
            );
        };
    }

    #[test]
    fn scan_idx_layouts_match_skel() {
        use crate::tests::test_skb_scanner_skel::types as skel;

        assert_size!(ScanIpv4Idx, skel::scan_ipv4_idx);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, l4_offset);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, fragment_off);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, fragment_id);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, l4_protocol);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, fragment_type);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, pkt_type);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, icmp_error_l3_offset);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, icmp_error_inner_l4_offset);
        assert_field!(ScanIpv4Idx, skel::scan_ipv4_idx, icmp_error_l4_protocol);

        assert_size!(ScanIpv6Idx, skel::scan_ipv6_idx);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, l4_offset);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, fragment_off);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, fragment_id);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, l4_protocol);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, fragment_type);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, pkt_type);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, icmp_error_l3_offset);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, icmp_error_inner_l4_offset);
        assert_field!(ScanIpv6Idx, skel::scan_ipv6_idx, icmp_error_l4_protocol);
    }

    #[test]
    fn scanner_result_layouts_match_skel() {
        use crate::tests::test_skb_scanner_skel::types as skb_skel;
        use crate::tests::test_xdp_scanner_skel::types as xdp_skel;

        assert_size!(SkbScanResult, skb_skel::skb_scan_test_result);
        assert_field!(SkbScanResult, skb_skel::skb_scan_test_result, scan_ret);
        assert_field!(SkbScanResult, skb_skel::skb_scan_test_result, l3_proto);
        assert_field!(SkbScanResult, skb_skel::skb_scan_test_result, v4.l4_offset);
        assert_field!(SkbScanResult, skb_skel::skb_scan_test_result, v4.pkt_type);
        assert_field!(SkbScanResult, skb_skel::skb_scan_test_result, v6.fragment_id);
        assert_field!(SkbScanResult, skb_skel::skb_scan_test_result, v6.pkt_type);

        assert_size!(SkbScanResult, xdp_skel::xdp_scan_test_result);
        assert_field!(SkbScanResult, xdp_skel::xdp_scan_test_result, scan_ret);
        assert_field!(SkbScanResult, xdp_skel::xdp_scan_test_result, l3_proto);
        assert_field!(SkbScanResult, xdp_skel::xdp_scan_test_result, v4.l4_offset);
        assert_field!(SkbScanResult, xdp_skel::xdp_scan_test_result, v6.fragment_id);

        assert_size!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result);
        assert_field!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result, scan_ret);
        assert_field!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result, l3_proto);
        assert_field!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result, icmp_error_l3_offset);
        assert_field!(
            SkbIcmpTestResult,
            skb_skel::skb_icmp_test_result,
            icmp_error_inner_l4_offset
        );
        assert_field!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result, icmp_error_l4_protocol);
        assert_field!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result, pkt_type);
        assert_field!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result, v4_saddr);
        assert_field!(SkbIcmpTestResult, skb_skel::skb_icmp_test_result, v6_saddr);
    }

    #[test]
    fn skb_read_result_layouts_match_skel() {
        use crate::tests::test_skb_read_skel::types as skel;

        assert_size!(SkbReadTestResult, skel::skb_read_test_result);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, l3_proto);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, scan_ret);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, read_l3_ret);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, read_info_ret);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v4_idx.l4_offset);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v4_idx.pkt_type);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v6_idx.l4_offset);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v6_idx.fragment_id);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v4_l3_saddr);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v4_l3_daddr);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v6_l3_saddr);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v6_l3_daddr);
        assert_field_as!(
            SkbReadTestResult,
            v4_info.src_addr,
            skel::skb_read_test_result,
            v4_info.src_addr.addr
        );
        assert_field_as!(
            SkbReadTestResult,
            v4_info.dst_addr,
            skel::skb_read_test_result,
            v4_info.dst_addr.addr
        );
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v4_info.src_port);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v4_info.dst_port);
        assert_field_as!(
            SkbReadTestResult,
            v6_info.src_addr,
            skel::skb_read_test_result,
            v6_info.src_addr.ip
        );
        assert_field_as!(
            SkbReadTestResult,
            v6_info.dst_addr,
            skel::skb_read_test_result,
            v6_info.dst_addr.bits
        );
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v6_info.src_port);
        assert_field!(SkbReadTestResult, skel::skb_read_test_result, v6_info.dst_port);
    }

    #[test]
    fn packet_offset_info_layouts_match_skel() {
        use crate::tests::test_route_packet::types as route_skel;
        use crate::tests::test_tproxy_packet::types as tproxy_skel;

        assert_size!(PacketOffsetInfo, route_skel::packet_offset_info);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, icmp_error_l3_protocol);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, icmp_error_l4_protocol);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, status);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, pkt_type);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, l3_protocol);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, l4_protocol);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, fragment_type);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, fragment_off);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, fragment_id);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, l4_offset);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, l3_offset_when_scan);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, icmp_error_l3_offset);
        assert_field!(PacketOffsetInfo, route_skel::packet_offset_info, icmp_error_inner_l4_offset);

        assert_size!(PacketOffsetInfo, tproxy_skel::packet_offset_info);
    }

    #[test]
    fn tproxy_and_route_result_layouts_match_skel() {
        use crate::tests::test_route_packet::types as route_skel;
        use crate::tests::test_tproxy_packet::types as tproxy_skel;

        assert_size!(TproxyPacketTestResult, tproxy_skel::tproxy_packet_test_result);
        assert_field!(
            TproxyPacketTestResult,
            tproxy_skel::tproxy_packet_test_result,
            offset.l3_protocol
        );
        assert_field!(
            TproxyPacketTestResult,
            tproxy_skel::tproxy_packet_test_result,
            offset.l4_offset
        );
        assert_field_as!(
            TproxyPacketTestResult,
            pair.src_addr,
            tproxy_skel::tproxy_packet_test_result,
            pair.src_addr.ip
        );
        assert_field_as!(
            TproxyPacketTestResult,
            pair.dst_addr,
            tproxy_skel::tproxy_packet_test_result,
            pair.dst_addr.bits
        );
        assert_field!(
            TproxyPacketTestResult,
            tproxy_skel::tproxy_packet_test_result,
            pair.src_port
        );
        assert_field!(
            TproxyPacketTestResult,
            tproxy_skel::tproxy_packet_test_result,
            pair.dst_port
        );
        assert_field!(TproxyPacketTestResult, tproxy_skel::tproxy_packet_test_result, scan_ret);
        assert_field!(TproxyPacketTestResult, tproxy_skel::tproxy_packet_test_result, read_ret);

        assert_size!(RoutePacketTestResult, route_skel::route_packet_test_result);
        assert_field!(
            RoutePacketTestResult,
            route_skel::route_packet_test_result,
            offset.l3_protocol
        );
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.saddr);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.daddr);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.l4_protocol);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.smac);
        assert_field_as!(
            RoutePacketTestResult,
            v6.saddr,
            route_skel::route_packet_test_result,
            v6.saddr.ip
        );
        assert_field_as!(
            RoutePacketTestResult,
            v6.daddr,
            route_skel::route_packet_test_result,
            v6.daddr.bytes
        );
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v6.l4_protocol);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v6.smac);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, scan_ret);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, read_ret);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, forward_ret);
    }

    /// The `map_types` NAT mirrors are used by both runtime (tc/share skel)
    /// and tests (xdp skel); cross-check against the xdp skel here to make
    /// sure both generated skeletons agree on the layout.
    #[test]
    fn nat_timer_layouts_match_xdp_skel() {
        use crate::map_types::{Nat4TimerKey, Nat4TimerValueV3, Nat6TimerKey, Nat6TimerValue};
        use crate::tests::xdp_nat_skel::types as xdp;

        assert_size!(Nat4TimerKey, xdp::nat4_timer_key);
        assert_field!(Nat4TimerKey, xdp::nat4_timer_key, l4proto);
        assert_field_as!(Nat4TimerKey, src_addr, xdp::nat4_timer_key, pair_ip.src_addr.addr);
        assert_field_as!(Nat4TimerKey, dst_addr, xdp::nat4_timer_key, pair_ip.dst_addr.addr);
        assert_field_as!(Nat4TimerKey, src_port, xdp::nat4_timer_key, pair_ip.src_port);
        assert_field_as!(Nat4TimerKey, dst_port, xdp::nat4_timer_key, pair_ip.dst_port);

        assert_size!(Nat4TimerValueV3, xdp::nat4_timer_value_v3);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, server_status);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, client_status);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, status);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, timer);
        assert_field_as!(Nat4TimerValueV3, client_addr, xdp::nat4_timer_value_v3, client_addr.addr);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, client_port);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, gress);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, ifindex);
        assert_field!(Nat4TimerValueV3, xdp::nat4_timer_value_v3, is_static);

        assert_size!(Nat6TimerKey, xdp::nat6_timer_key);
        assert_field!(Nat6TimerKey, xdp::nat6_timer_key, client_suffix);
        assert_field!(Nat6TimerKey, xdp::nat6_timer_key, client_port);
        assert_field!(Nat6TimerKey, xdp::nat6_timer_key, id_byte);
        assert_field!(Nat6TimerKey, xdp::nat6_timer_key, l4_protocol);

        assert_size!(Nat6TimerValue, xdp::nat6_timer_value);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, timer);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, server_status);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, status);
        assert_field_as!(Nat6TimerValue, trigger_addr, xdp::nat6_timer_value, trigger_addr.bytes);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, trigger_port);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, is_allow_reuse);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, is_static);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, need_prefix_replace);
        assert_field!(Nat6TimerValue, xdp::nat6_timer_value, client_prefix);
    }
}
