//! `firewall_block_ip4` / `firewall_block_ip6` LPM maps (see
//! `share_map.skel.rs`).

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Ipv4LpmKey {
    pub prefixlen: u32,
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Ipv6LpmKey {
    pub prefixlen: u32,
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct FirewallAction {
    pub mark: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::share_map::types as share;

    #[test]
    fn firewall_layouts_match_skel() {
        assert_size!(Ipv4LpmKey, share::ipv4_lpm_key);
        assert_field!(Ipv4LpmKey, share::ipv4_lpm_key, prefixlen);
        assert_field!(Ipv4LpmKey, share::ipv4_lpm_key, addr);

        assert_size!(Ipv6LpmKey, share::ipv6_lpm_key);
        assert_field!(Ipv6LpmKey, share::ipv6_lpm_key, prefixlen);
        assert_field!(Ipv6LpmKey, share::ipv6_lpm_key, addr);

        assert_size!(FirewallAction, share::firewall_action);
        assert_field!(FirewallAction, share::firewall_action, mark);
    }
}
