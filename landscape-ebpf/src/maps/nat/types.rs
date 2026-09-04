//! `nat4`/`nat6_static_map`, dynamic `nat4`/`nat6` maps, timer maps and the
//! port queue (see `share_map.skel.rs`).

use zerocopy::{FromBytes, Immutable, IntoBytes};

/// C side `nat4_mapping_key` (shared by static and dynamic NAT maps).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct NatMappingKeyV4 {
    pub gress: u8,
    pub l4proto: u8,
    pub from_port: u16,
    pub from_addr: u32,
}

/// C side `nat4_static_value`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat4StMappingValue {
    pub addr: u32,
    pub port: u16,
    pub _pad: [u8; 2],
}

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

/// C side `nat4_mapping_value_v3`. Only constructed by tests today, but kept
/// here next to its siblings so all NAT wire types live in one place.
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat4MappingValueV3 {
    pub state_ref: u64,
    pub addr: u32,
    pub trigger_addr: u32,
    pub port: u16,
    pub trigger_port: u16,
    pub generation: u16,
    pub _pad: u8,
    pub is_allow_reuse: u8,
}

/// C side `nat4_egress_mapping_value_v3`. Test-only today (see
/// [`Nat4MappingValueV3`]).
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat4EgressMappingValueV3 {
    pub addr: u32,
    pub port: u16,
    pub trigger_port: u16,
    pub trigger_addr: u32,
    pub is_allow_reuse: u8,
    pub _pad: [u8; 3],
}

/// C side `nat4_port_queue_value_v3`. Test-only today (see
/// [`Nat4MappingValueV3`]).
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat4PortQueueValueV3 {
    pub port: u16,
    pub last_generation: u16,
}

/// C side `nat4_timer_key`; the nested `inet4_pair` / `inet4_addr` structs
/// are flattened into scalar fields. Test-only today (see
/// [`Nat4MappingValueV3`]).
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat4TimerKey {
    pub l4proto: u8,
    pub _pad: [u8; 3],
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
}

/// C side `nat4_timer_value_v3`; `bpf_timer` is 16 bytes of opaque data,
/// mirrored as a byte array. Test-only today (see [`Nat4MappingValueV3`]).
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat4TimerValueV3 {
    pub server_status: u64,
    pub client_status: u64,
    pub status: u64,
    pub timer: [u8; 16],
    pub client_addr: u32,
    pub client_port: u16,
    pub gress: u8,
    pub flow_id: u8,
    pub create_time: u64,
    pub ingress_bytes: u64,
    pub ingress_packets: u64,
    pub egress_bytes: u64,
    pub egress_packets: u64,
    pub cpu_id: u32,
    pub ifindex: u32,
    pub generation_snapshot: u16,
    pub is_static: u8,
    pub _pad: u8,
    pub __pad_100: [u8; 4],
}

/// C side `nat6_timer_key`. Test-only today (see [`Nat4MappingValueV3`]).
#[cfg_attr(not(test), allow(dead_code))]
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, FromBytes, IntoBytes, Immutable, PartialEq, Eq)]
pub(crate) struct Nat6TimerKey {
    pub client_suffix: [u8; 8],
    pub client_port: u16,
    pub id_byte: u8,
    pub l4_protocol: u8,
}

/// C side `nat6_timer_value`. Test-only today (see [`Nat4MappingValueV3`]).
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
    use crate::maps::share_map::types as share;

    #[test]
    fn nat_layouts_match_skel() {
        assert_size!(NatMappingKeyV4, share::nat4_mapping_key);
        assert_field!(NatMappingKeyV4, share::nat4_mapping_key, gress);
        assert_field!(NatMappingKeyV4, share::nat4_mapping_key, l4proto);
        assert_field!(NatMappingKeyV4, share::nat4_mapping_key, from_port);
        assert_field!(NatMappingKeyV4, share::nat4_mapping_key, from_addr);

        assert_size!(Nat4StMappingValue, share::nat4_static_value);
        assert_field!(Nat4StMappingValue, share::nat4_static_value, addr);
        assert_field!(Nat4StMappingValue, share::nat4_static_value, port);

        assert_size!(StaticNat6MappingKey, share::static_nat6_mapping_key);
        assert_field!(StaticNat6MappingKey, share::static_nat6_mapping_key, port);
        assert_field!(StaticNat6MappingKey, share::static_nat6_mapping_key, l4_protocol);
        assert_field!(StaticNat6MappingKey, share::static_nat6_mapping_key, ip_suffix);

        assert_size!(StaticNat6MappingValue, share::static_nat6_mapping_value);
        assert_field!(StaticNat6MappingValue, share::static_nat6_mapping_value, lan_prefix);

        assert_size!(Nat4MappingValueV3, share::nat4_mapping_value_v3);
        assert_field!(Nat4MappingValueV3, share::nat4_mapping_value_v3, state_ref);
        assert_field!(Nat4MappingValueV3, share::nat4_mapping_value_v3, addr);
        assert_field!(Nat4MappingValueV3, share::nat4_mapping_value_v3, trigger_addr);
        assert_field!(Nat4MappingValueV3, share::nat4_mapping_value_v3, port);
        assert_field!(Nat4MappingValueV3, share::nat4_mapping_value_v3, trigger_port);
        assert_field!(Nat4MappingValueV3, share::nat4_mapping_value_v3, generation);
        assert_field!(Nat4MappingValueV3, share::nat4_mapping_value_v3, is_allow_reuse);

        assert_size!(Nat4EgressMappingValueV3, share::nat4_egress_mapping_value_v3);
        assert_field!(Nat4EgressMappingValueV3, share::nat4_egress_mapping_value_v3, addr);
        assert_field!(Nat4EgressMappingValueV3, share::nat4_egress_mapping_value_v3, port);
        assert_field!(Nat4EgressMappingValueV3, share::nat4_egress_mapping_value_v3, trigger_port);
        assert_field!(Nat4EgressMappingValueV3, share::nat4_egress_mapping_value_v3, trigger_addr);
        assert_field!(
            Nat4EgressMappingValueV3,
            share::nat4_egress_mapping_value_v3,
            is_allow_reuse
        );

        assert_size!(Nat4PortQueueValueV3, share::nat4_port_queue_value_v3);
        assert_field!(Nat4PortQueueValueV3, share::nat4_port_queue_value_v3, port);
        assert_field!(Nat4PortQueueValueV3, share::nat4_port_queue_value_v3, last_generation);

        assert_size!(Nat4TimerKey, share::nat4_timer_key);
        assert_field!(Nat4TimerKey, share::nat4_timer_key, l4proto);
        assert_field_as!(Nat4TimerKey, src_addr, share::nat4_timer_key, pair_ip.src_addr.addr);
        assert_field_as!(Nat4TimerKey, dst_addr, share::nat4_timer_key, pair_ip.dst_addr.addr);
        assert_field_as!(Nat4TimerKey, src_port, share::nat4_timer_key, pair_ip.src_port);
        assert_field_as!(Nat4TimerKey, dst_port, share::nat4_timer_key, pair_ip.dst_port);

        assert_size!(Nat4TimerValueV3, share::nat4_timer_value_v3);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, server_status);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, client_status);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, status);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, timer);
        assert_field_as!(
            Nat4TimerValueV3,
            client_addr,
            share::nat4_timer_value_v3,
            client_addr.addr
        );
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, client_port);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, gress);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, flow_id);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, create_time);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, ingress_bytes);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, ingress_packets);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, egress_bytes);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, egress_packets);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, cpu_id);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, ifindex);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, generation_snapshot);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, is_static);
        assert_field!(Nat4TimerValueV3, share::nat4_timer_value_v3, __pad_100);

        assert_size!(Nat6TimerKey, share::nat6_timer_key);
        assert_field!(Nat6TimerKey, share::nat6_timer_key, client_suffix);
        assert_field!(Nat6TimerKey, share::nat6_timer_key, client_port);
        assert_field!(Nat6TimerKey, share::nat6_timer_key, id_byte);
        assert_field!(Nat6TimerKey, share::nat6_timer_key, l4_protocol);

        assert_size!(Nat6TimerValue, share::nat6_timer_value);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, timer);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, server_status);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, client_status);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, status);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, trigger_addr);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, trigger_port);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, is_allow_reuse);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, flow_id);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, gress);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, is_static);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, need_prefix_replace);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, create_time);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, ingress_bytes);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, ingress_packets);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, egress_bytes);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, egress_packets);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, cpu_id);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, ifindex);
        assert_field!(Nat6TimerValue, share::nat6_timer_value, client_prefix);
    }
}
