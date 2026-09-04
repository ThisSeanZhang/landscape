//! `ip_mac_v4` / `ip_mac_v6` maps (see `neigh_update.skel.rs`).

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct MacKeyV4 {
    pub addr: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct MacKeyV6 {
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct MacValueV4 {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub dev_mac: [u8; 6],
    pub proto: u16,
    pub _pad_tail: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct MacValueV6 {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub dev_mac: [u8; 6],
    pub proto: u16,
    pub sourced: u8,
    pub _pad_tail: [u8; 1],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::mac::neigh_update::types as neigh;

    #[test]
    fn mac_layouts_match_skel() {
        assert_size!(MacKeyV4, neigh::mac_key_v4);
        assert_field!(MacKeyV4, neigh::mac_key_v4, addr);

        assert_size!(MacKeyV6, neigh::mac_key_v6);
        assert_field!(MacKeyV6, neigh::mac_key_v6, addr);

        assert_size!(MacValueV4, neigh::mac_value_v4);
        assert_field!(MacValueV4, neigh::mac_value_v4, ifindex);
        assert_field!(MacValueV4, neigh::mac_value_v4, mac);
        assert_field!(MacValueV4, neigh::mac_value_v4, dev_mac);
        assert_field!(MacValueV4, neigh::mac_value_v4, proto);

        assert_size!(MacValueV6, neigh::mac_value_v6);
        assert_field!(MacValueV6, neigh::mac_value_v6, ifindex);
        assert_field!(MacValueV6, neigh::mac_value_v6, mac);
        assert_field!(MacValueV6, neigh::mac_value_v6, dev_mac);
        assert_field!(MacValueV6, neigh::mac_value_v6, proto);
        assert_field!(MacValueV6, neigh::mac_value_v6, sourced);
    }
}
