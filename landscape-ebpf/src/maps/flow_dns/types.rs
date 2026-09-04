//! Per-flow DNS rule keys/values (`flow4_dns_map` / `flow6_dns_map` inner
//! hash maps).

use zerocopy::{FromBytes, Immutable, IntoBytes};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::share_map::types as share;

    #[test]
    fn flow_dns_layouts_match_skel() {
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
    }
}
