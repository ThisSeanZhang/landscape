//! Flow-match LPM key (`flow_match_map`, value is a plain `u32` flow_id).

use std::net::Ipv6Addr;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::maps::Inet6Bytes;

/// LPM key of `flow_match_map`. The C tail is
/// `union { u_inet_addr src_addr; struct { u8 mac[6]; } mac; }`, mirrored as
/// `[u8; 16]` plus accessors.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowMatchKey {
    pub prefixlen: u32,
    pub l3_protocol: u8,
    pub is_match_ip: u8,
    pub _pad: [u8; 2],
    pub addr: [u8; 16],
}

impl FlowMatchKey {
    pub fn set_src_mac(&mut self, mac: [u8; 6]) {
        self.addr[..6].copy_from_slice(&mac);
    }

    pub fn set_src_ipv4_be(&mut self, addr: u32) {
        self.addr.set_ipv4_be(addr);
    }

    pub fn set_src_ipv6(&mut self, addr: Ipv6Addr) {
        self.addr.set_ipv6(addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::xdp_wan_route::xdp_wan_route_skel::types as share;

    #[test]
    fn flow_match_key_layouts_match_skel() {
        assert_size!(FlowMatchKey, share::flow_match_key);
        assert_field!(FlowMatchKey, share::flow_match_key, prefixlen);
        assert_field!(FlowMatchKey, share::flow_match_key, l3_protocol);
        assert_field!(FlowMatchKey, share::flow_match_key, is_match_ip);
        assert_field_as!(FlowMatchKey, addr, share::flow_match_key, __anon_flow_match_key_1);
    }

    /// Standalone byte-level check: hand-written expected bytes without going
    /// through skel types, guarding against mirror and skel being wrong
    /// together (two wrongs making a right).
    #[allow(clippy::field_reassign_with_default)]
    #[test]
    fn flow_match_key_wire_bytes() {
        let mac = [0x02u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut key = FlowMatchKey::default();
        key.prefixlen = 80;
        key.l3_protocol = 0;
        key.is_match_ip = 0;
        key.set_src_mac(mac);

        let mut expected = [0u8; 24];
        expected[..4].copy_from_slice(&80u32.to_ne_bytes());
        expected[8..14].copy_from_slice(&mac);
        assert_eq!(key.as_bytes(), &expected);

        let mut key = FlowMatchKey::default();
        key.prefixlen = 64;
        key.l3_protocol = 0x08;
        key.is_match_ip = 1;
        key.set_src_ipv4_be(u32::from_be_bytes([203, 0, 113, 1]));

        let mut expected = [0u8; 24];
        expected[..4].copy_from_slice(&64u32.to_ne_bytes());
        expected[4] = 0x08;
        expected[5] = 1;
        expected[8..12].copy_from_slice(&[203, 0, 113, 1]);
        assert_eq!(key.as_bytes(), &expected);
    }
}
