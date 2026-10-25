//! `nat6_static_map` and the NAT6 timer wire types.

use zerocopy::{FromBytes, Immutable, IntoBytes};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct StaticNat6MappingKey {
    pub port: u16,
    pub l4_protocol: u8,
    pub _pad: u8,
    pub ip_suffix: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct StaticNat6MappingValue {
    pub lan_prefix: [u8; 8],
}

/// C side `nat6_timer_key`. Test-only today.
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat6TimerKey {
    pub client_suffix: [u8; 8],
    pub client_port: u16,
    pub id_byte: u8,
    pub l4_protocol: u8,
}

/// C side `nat6_timer_value`. Test-only today.
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat6TimerValue {
    pub timer: [u8; 16],
    pub server_status: u64,
    pub client_status: u64,
    pub status: u64,
    pub trigger_addr: [u8; 16],
    pub trigger_port: u16,
    pub is_allow_reuse: u8,
    pub flow_id: u8,
    pub gress: u8,
    pub is_static: u8,
    pub need_prefix_replace: u8,
    pub _pad: u8,
    pub create_time: u64,
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
    pub cpu_id: u32,
    pub ifindex: u32,
    pub client_prefix: [u8; 8],
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skel::xdp_nat6::types as share6;

    #[test]
    fn nat_layouts_match_skel() {
        assert_size!(StaticNat6MappingKey, share6::static_nat6_mapping_key);
        assert_field!(StaticNat6MappingKey, share6::static_nat6_mapping_key, port);
        assert_field!(StaticNat6MappingKey, share6::static_nat6_mapping_key, l4_protocol);
        assert_field!(StaticNat6MappingKey, share6::static_nat6_mapping_key, ip_suffix);

        assert_size!(StaticNat6MappingValue, share6::static_nat6_mapping_value);
        assert_field!(StaticNat6MappingValue, share6::static_nat6_mapping_value, lan_prefix);

        assert_size!(Nat6TimerKey, share6::nat6_timer_key);
        assert_field!(Nat6TimerKey, share6::nat6_timer_key, client_suffix);
        assert_field!(Nat6TimerKey, share6::nat6_timer_key, client_port);
        assert_field!(Nat6TimerKey, share6::nat6_timer_key, id_byte);
        assert_field!(Nat6TimerKey, share6::nat6_timer_key, l4_protocol);

        assert_size!(Nat6TimerValue, share6::nat6_timer_value);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, timer);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, server_status);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, client_status);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, status);
        assert_field_as!(
            Nat6TimerValue,
            trigger_addr,
            share6::nat6_timer_value,
            trigger_addr.in6_u.u6_addr8
        );
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, trigger_port);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, is_allow_reuse);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, is_static);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, need_prefix_replace);
        assert_field!(Nat6TimerValue, share6::nat6_timer_value, client_prefix);
    }
}
