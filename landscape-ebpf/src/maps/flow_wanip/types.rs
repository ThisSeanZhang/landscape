//! Per-flow WAN-IP trie keys/values (`flow4_ip_map` / `flow6_ip_map` inner
//! LPM tries).

use zerocopy::{FromBytes, Immutable, IntoBytes};

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
    use crate::chain::xdp_wan_route::xdp_wan_route_skel::types as share;

    #[test]
    fn flow_ip_trie_layouts_match_skel() {
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
}
