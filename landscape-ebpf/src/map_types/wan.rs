//! `wan_ip_binding` map (see `share_map.skel.rs`).

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct WanIpInfoKey {
    pub ifindex: u32,
    pub l3_protocol: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct WanIpInfoValue {
    pub addr: [u8; 16],
    pub gateway: [u8; 16],
    pub mask: u8,
    pub has_mac: u8,
    pub mac: [u8; 6],
    pub npt_mask: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map_setting::share_map::types as share;
    use crate::map_types::Inet6Bytes;

    #[test]
    fn wan_ip_layouts_match_skel() {
        assert_size!(WanIpInfoKey, share::wan_ip_info_key);
        assert_field!(WanIpInfoKey, share::wan_ip_info_key, ifindex);
        assert_field!(WanIpInfoKey, share::wan_ip_info_key, l3_protocol);

        assert_size!(WanIpInfoValue, share::wan_ip_info_value);
        assert_field!(WanIpInfoValue, share::wan_ip_info_value, addr);
        assert_field!(WanIpInfoValue, share::wan_ip_info_value, gateway);
        assert_field!(WanIpInfoValue, share::wan_ip_info_value, mask);
        assert_field!(WanIpInfoValue, share::wan_ip_info_value, has_mac);
        assert_field!(WanIpInfoValue, share::wan_ip_info_value, mac);
        assert_field!(WanIpInfoValue, share::wan_ip_info_value, npt_mask);
    }

    /// Standalone byte-level check: hand-written expected bytes without going
    /// through skel types, guarding against mirror and skel being wrong
    /// together (two wrongs making a right).
    #[test]
    fn wan_ip_info_value_wire_bytes() {
        let mut value = WanIpInfoValue::default();
        value.addr.set_ipv4_be(u32::from_be_bytes([203, 0, 113, 1]));
        value.gateway.set_ipv6("2001:db8::1".parse().unwrap());
        value.mask = 24;
        value.has_mac = 1;
        value.mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        value.npt_mask = 0x00FF_00FF_00FF_00FF;

        let mut expected = [0u8; 48];
        expected[0..4].copy_from_slice(&[203, 0, 113, 1]);
        expected[16..32]
            .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01]);
        expected[32] = 24;
        expected[33] = 1;
        expected[34..40].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        expected[40..48].copy_from_slice(&0x00FF_00FF_00FF_00FFu64.to_ne_bytes());
        assert_eq!(value.as_bytes(), &expected);
    }
}
