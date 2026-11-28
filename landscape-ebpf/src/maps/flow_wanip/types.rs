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

pub(crate) const FLOW_L4_MAX_RULES_PER_FLOW: usize = 32;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowL4RuleEntry {
    pub mark: u32,
    pub start_port: u16,
    pub end_port: u16,
    pub priority: u16,
    pub l4_proto: u8,
    pub _pad: [u8; 5],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowL4RuleSet {
    pub count: u32,
    pub entries: [FlowL4RuleEntry; FLOW_L4_MAX_RULES_PER_FLOW],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FlowL4Meta {
    pub active_mask_words: [u32; 8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skel::xdp_wan_route::types as share;

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

        assert_size!(FlowL4RuleEntry, share::flow_l4_rule_entry);
        assert_field!(FlowL4RuleEntry, share::flow_l4_rule_entry, mark);
        assert_field!(FlowL4RuleEntry, share::flow_l4_rule_entry, start_port);
        assert_field!(FlowL4RuleEntry, share::flow_l4_rule_entry, end_port);
        assert_field!(FlowL4RuleEntry, share::flow_l4_rule_entry, priority);
        assert_field!(FlowL4RuleEntry, share::flow_l4_rule_entry, l4_proto);
        assert_field!(FlowL4RuleEntry, share::flow_l4_rule_entry, _pad);

        assert_size!(FlowL4RuleSet, share::flow_l4_rule_set);
        assert_field!(FlowL4RuleSet, share::flow_l4_rule_set, count);
        assert_field!(FlowL4RuleSet, share::flow_l4_rule_set, entries);

        assert_size!(FlowL4Meta, share::flow_l4_meta);
        assert_field!(FlowL4Meta, share::flow_l4_meta, active_mask_words);
    }
}
