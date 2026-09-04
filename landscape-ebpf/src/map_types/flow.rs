//! `flow_match_map` / `flow4_dns_map` / `flow4_ip_map` etc. (see
//! `share_map.skel.rs`).

use std::net::Ipv6Addr;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::Inet6Bytes;

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

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowDnsMatchKeyV4 {
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowDnsMatchKeyV6 {
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowDnsMatchValueV4 {
    pub mark: u32,
    pub priority: u16,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowDnsMatchValueV6 {
    pub mark: u32,
    pub priority: u16,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowIpTrieKeyV4 {
    pub prefixlen: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowIpTrieKeyV6 {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowIpTrieValueV4 {
    pub mark: u32,
    pub priority: u16,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowIpTrieValueV6 {
    pub mark: u32,
    pub priority: u16,
    pub _pad: [u8; 2],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map_setting::share_map::types as share;

    #[test]
    fn flow_layouts_match_skel() {
        assert_size!(FlowMatchKey, share::flow_match_key);
        assert_field!(FlowMatchKey, share::flow_match_key, prefixlen);
        assert_field!(FlowMatchKey, share::flow_match_key, l3_protocol);
        assert_field!(FlowMatchKey, share::flow_match_key, is_match_ip);
        assert_field_as!(FlowMatchKey, addr, share::flow_match_key, __anon_flow_match_key_1);

        assert_size!(FlowDnsMatchKeyV4, share::flow_dns_match_key_v4);
        assert_field!(FlowDnsMatchKeyV4, share::flow_dns_match_key_v4, addr);

        assert_size!(FlowDnsMatchKeyV6, share::flow_dns_match_key_v6);
        assert_field!(FlowDnsMatchKeyV6, share::flow_dns_match_key_v6, addr);

        assert_size!(FlowDnsMatchValueV4, share::flow_dns_match_value_v4);
        assert_field!(FlowDnsMatchValueV4, share::flow_dns_match_value_v4, mark);
        assert_field!(FlowDnsMatchValueV4, share::flow_dns_match_value_v4, priority);

        assert_size!(FlowDnsMatchValueV6, share::flow_dns_match_value_v6);
        assert_field!(FlowDnsMatchValueV6, share::flow_dns_match_value_v6, mark);
        assert_field!(FlowDnsMatchValueV6, share::flow_dns_match_value_v6, priority);

        assert_size!(FlowIpTrieKeyV4, share::flow_ip_trie_key_v4);
        assert_field!(FlowIpTrieKeyV4, share::flow_ip_trie_key_v4, prefixlen);
        assert_field!(FlowIpTrieKeyV4, share::flow_ip_trie_key_v4, addr);

        assert_size!(FlowIpTrieKeyV6, share::flow_ip_trie_key_v6);
        assert_field!(FlowIpTrieKeyV6, share::flow_ip_trie_key_v6, prefixlen);
        assert_field!(FlowIpTrieKeyV6, share::flow_ip_trie_key_v6, addr);

        assert_size!(FlowIpTrieValueV4, share::flow_ip_trie_value_v4);
        assert_field!(FlowIpTrieValueV4, share::flow_ip_trie_value_v4, mark);
        assert_field!(FlowIpTrieValueV4, share::flow_ip_trie_value_v4, priority);

        assert_size!(FlowIpTrieValueV6, share::flow_ip_trie_value_v6);
        assert_field!(FlowIpTrieValueV6, share::flow_ip_trie_value_v6, mark);
        assert_field!(FlowIpTrieValueV6, share::flow_ip_trie_value_v6, priority);
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
