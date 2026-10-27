//! Mirror types for test-only eBPF output snapshots (result map values of
//! test_tproxy_packet / test_route_packet and the reader tests).
//!
//! Same conventions as `crate::maps`: layouts are pinned by layout
//! consistency tests; the C address type (`struct in6_addr`) is modeled
//! as `[u8; 16]`; implicit padding is spelled out explicitly. These types are
//! decode-only, so only `FromBytes` is derived.

use zerocopy::{FromBytes, Immutable};

/// C side `inet_pair` (union-address flavor, test_tproxy_packet).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct InetPair {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
}

/// C side `reader_test_result` (test_tc_read_head4).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct TcReadHead4Result {
    pub read_ret: i32,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub l3_offset: u16,
    pub l4_offset: u16,
    pub sport: u16,
    pub dport: u16,
    pub icmp_inner_l4_offset: u16,
    pub l4_protocol: u8,
    pub tcp_phase: u8,
    pub frag_code: u8,
    pub ports_valid: u8,
    pub icmp_inner_l4_protocol: u8,
    pub _pad: [u8; 1],
}

/// C side `reader_test_result` (test_tc_read_head6).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct TcReadHead6Result {
    pub read_ret: i32,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub l3_offset: u16,
    pub l4_offset: u16,
    pub sport: u16,
    pub dport: u16,
    pub icmp_inner_l4_offset: u16,
    pub l4_protocol: u8,
    pub tcp_phase: u8,
    pub frag_code: u8,
    pub ports_valid: u8,
    pub icmp_inner_l4_protocol: u8,
    pub _pad: [u8; 1],
}

/// C side `xdp_reader_test_result` (test_xdp_read_head6).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct XdpReadHead6Result {
    pub read_ret: i32,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub l4_offset: u16,
    pub sport: u16,
    pub dport: u16,
    pub icmp_inner_l4_offset: u16,
    pub l4_protocol: u8,
    pub tcp_phase: u8,
    pub frag_code: u8,
    pub ports_valid: u8,
    pub icmp_inner_l4_protocol: u8,
    pub _pad: [u8; 3],
}

// =============================================================================
// tproxy / route packet
// =============================================================================

/// C side `tproxy_view`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct TproxyView {
    pub l3_protocol: u8,
    pub l4_protocol: u8,
    pub l4_offset: u16,
}

/// C side `tproxy_packet_test_result`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct TproxyPacketTestResult {
    pub view: TproxyView,
    pub pair: InetPair,
    pub scan_ret: i32,
    pub read_ret: i32,
}

/// C side `route4_context`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteContextV4 {
    pub saddr: u32,
    pub daddr: u32,
    pub l4_protocol: u8,
    pub tos: u8,
    pub smac: [u8; 6],
}

/// C side `route6_context`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteContextV6 {
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub l4_protocol: u8,
    pub tos: u8,
    pub smac: [u8; 6],
}

/// C side `route_view`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RouteView {
    pub l3_offset: u32,
    pub l3_protocol: u8,
}

/// C side `route_packet_test_result`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, Immutable, PartialEq, Eq)]
pub(crate) struct RoutePacketTestResult {
    pub route: RouteView,
    pub v4: RouteContextV4,
    pub v6: RouteContextV6,
    pub scan_ret: i32,
    pub read_ret: i32,
    pub forward_ret: i32,
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use crate::tests::helper::wire::*;

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
    #[cfg(feature = "test-misc")]
    fn tproxy_view_layouts_match_skel() {
        use crate::tests::test_tproxy_packet::types as tproxy_skel;

        assert_size!(TproxyView, tproxy_skel::tproxy_view);
        assert_field!(TproxyView, tproxy_skel::tproxy_view, l3_protocol);
        assert_field!(TproxyView, tproxy_skel::tproxy_view, l4_protocol);
        assert_field!(TproxyView, tproxy_skel::tproxy_view, l4_offset);
    }

    #[test]
    #[cfg(all(feature = "test-route", feature = "test-misc"))]
    fn tproxy_and_route_result_layouts_match_skel() {
        use crate::tests::test_route_packet::types as route_skel;
        use crate::tests::test_tproxy_packet::types as tproxy_skel;

        assert_size!(TproxyPacketTestResult, tproxy_skel::tproxy_packet_test_result);
        assert_field!(
            TproxyPacketTestResult,
            tproxy_skel::tproxy_packet_test_result,
            view.l3_protocol
        );
        assert_field!(
            TproxyPacketTestResult,
            tproxy_skel::tproxy_packet_test_result,
            view.l4_offset
        );
        assert_field_as!(
            TproxyPacketTestResult,
            pair.src_addr,
            tproxy_skel::tproxy_packet_test_result,
            pair.src_addr.in6_u.u6_addr32
        );
        assert_field_as!(
            TproxyPacketTestResult,
            pair.dst_addr,
            tproxy_skel::tproxy_packet_test_result,
            pair.dst_addr.in6_u.u6_addr8
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

        assert_size!(RouteView, route_skel::route_view);
        assert_field!(RouteView, route_skel::route_view, l3_offset);
        assert_field!(RouteView, route_skel::route_view, l3_protocol);

        assert_size!(RoutePacketTestResult, route_skel::route_packet_test_result);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, route.l3_offset);
        assert_field!(
            RoutePacketTestResult,
            route_skel::route_packet_test_result,
            route.l3_protocol
        );
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.saddr);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.daddr);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.l4_protocol);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v4.smac);
        assert_field_as!(
            RoutePacketTestResult,
            v6.saddr,
            route_skel::route_packet_test_result,
            v6.saddr.in6_u.u6_addr32
        );
        assert_field_as!(
            RoutePacketTestResult,
            v6.daddr,
            route_skel::route_packet_test_result,
            v6.daddr.in6_u.u6_addr8
        );
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v6.l4_protocol);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, v6.smac);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, scan_ret);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, read_ret);
        assert_field!(RoutePacketTestResult, route_skel::route_packet_test_result, forward_ret);
    }

    /// The `maps` NAT mirrors are used by both runtime (tc/share skel)
    /// and tests (xdp skel); cross-check against the xdp skel here to make
    /// sure both generated skeletons agree on the layout.
    #[test]
    fn nat_timer_layouts_match_xdp_skel() {
        use crate::maps::{Nat6TimerKey, Nat6TimerValue};
        use crate::skel::xdp_nat6::types as xdp6;

        assert_size!(Nat6TimerKey, xdp6::nat6_timer_key);
        assert_field!(Nat6TimerKey, xdp6::nat6_timer_key, client_suffix);
        assert_field!(Nat6TimerKey, xdp6::nat6_timer_key, client_port);
        assert_field!(Nat6TimerKey, xdp6::nat6_timer_key, id_byte);
        assert_field!(Nat6TimerKey, xdp6::nat6_timer_key, l4_protocol);

        assert_size!(Nat6TimerValue, xdp6::nat6_timer_value);
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, timer);
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, server_status);
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, status);
        assert_field_as!(
            Nat6TimerValue,
            trigger_addr,
            xdp6::nat6_timer_value,
            trigger_addr.in6_u.u6_addr8
        );
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, trigger_port);
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, is_allow_reuse);
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, is_static);
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, need_prefix_replace);
        assert_field!(Nat6TimerValue, xdp6::nat6_timer_value, client_prefix);
    }
    #[test]
    #[cfg(feature = "test-reader")]
    fn tc_read_head4_result_layout_matches_skel() {
        use crate::tests::test_tc_read_head4_skel::types as skel;

        assert_size!(TcReadHead4Result, skel::reader_test_result);
        assert_field!(TcReadHead4Result, skel::reader_test_result, read_ret);
        assert_field!(TcReadHead4Result, skel::reader_test_result, src_addr);
        assert_field!(TcReadHead4Result, skel::reader_test_result, dst_addr);
        assert_field!(TcReadHead4Result, skel::reader_test_result, l3_offset);
        assert_field!(TcReadHead4Result, skel::reader_test_result, l4_offset);
        assert_field!(TcReadHead4Result, skel::reader_test_result, sport);
        assert_field!(TcReadHead4Result, skel::reader_test_result, dport);
        assert_field!(TcReadHead4Result, skel::reader_test_result, icmp_inner_l4_offset);
        assert_field!(TcReadHead4Result, skel::reader_test_result, l4_protocol);
        assert_field!(TcReadHead4Result, skel::reader_test_result, tcp_phase);
        assert_field!(TcReadHead4Result, skel::reader_test_result, frag_code);
        assert_field!(TcReadHead4Result, skel::reader_test_result, ports_valid);
        assert_field!(TcReadHead4Result, skel::reader_test_result, icmp_inner_l4_protocol);
    }

    #[test]
    #[cfg(feature = "test-reader")]
    fn tc_read_head6_result_layout_matches_skel() {
        use crate::tests::test_tc_read_head6_skel::types as skel;

        assert_size!(TcReadHead6Result, skel::reader_test_result);
        assert_field!(TcReadHead6Result, skel::reader_test_result, read_ret);
        assert_field!(TcReadHead6Result, skel::reader_test_result, src_addr);
        assert_field!(TcReadHead6Result, skel::reader_test_result, dst_addr);
        assert_field!(TcReadHead6Result, skel::reader_test_result, l3_offset);
        assert_field!(TcReadHead6Result, skel::reader_test_result, l4_offset);
        assert_field!(TcReadHead6Result, skel::reader_test_result, sport);
        assert_field!(TcReadHead6Result, skel::reader_test_result, dport);
        assert_field!(TcReadHead6Result, skel::reader_test_result, icmp_inner_l4_offset);
        assert_field!(TcReadHead6Result, skel::reader_test_result, l4_protocol);
        assert_field!(TcReadHead6Result, skel::reader_test_result, tcp_phase);
        assert_field!(TcReadHead6Result, skel::reader_test_result, frag_code);
        assert_field!(TcReadHead6Result, skel::reader_test_result, ports_valid);
        assert_field!(TcReadHead6Result, skel::reader_test_result, icmp_inner_l4_protocol);
    }

    #[test]
    #[cfg(feature = "test-reader")]
    fn xdp_read_head6_result_layout_matches_skel() {
        use crate::tests::test_xdp_read_head6_skel::types as skel;

        assert_size!(XdpReadHead6Result, skel::xdp_reader_test_result);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, read_ret);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, src_addr);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, dst_addr);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, l4_offset);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, sport);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, dport);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, icmp_inner_l4_offset);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, l4_protocol);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, tcp_phase);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, frag_code);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, ports_valid);
        assert_field!(XdpReadHead6Result, skel::xdp_reader_test_result, icmp_inner_l4_protocol);
    }
}
