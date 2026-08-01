use landscape_macro::LdApiError;

use crate::error::LdError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum LanIPv6Error {
    #[error("LAN IPv6 configuration has been modified. Please refresh and try again.")]
    #[api_error(id = "lan_ipv6.config_conflict", status = 409)]
    ConfigConflict,

    #[error(
        "LAN IPv6 prefix conflict: iface={iface_name}, group={group_id}, {service_kind} index={index_range} pool_len=/{pool_len} overlaps WAN-reserved /64 slot 0"
    )]
    #[api_error(id = "lan_ipv6.prefix_conflict.wan_reserved", status = 409)]
    WanReservedPrefixConflict {
        iface_name: String,
        group_id: String,
        service_kind: String,
        index_range: String,
        pool_len: u8,
    },

    #[error(
        "LAN IPv6 prefix conflict at /64 slot range {slot_range}: iface={left_iface_name}, group={left_group_id}, {left_service_kind} index={left_index_range} pool_len=/{left_pool_len} overlaps iface={right_iface_name}, group={right_group_id}, {right_service_kind} index={right_index_range} pool_len=/{right_pool_len}"
    )]
    #[api_error(id = "lan_ipv6.prefix_conflict.overlap", status = 409)]
    PrefixSlotOverlap {
        slot_range: String,
        left_iface_name: String,
        left_group_id: String,
        left_service_kind: String,
        left_index_range: String,
        left_pool_len: u8,
        right_iface_name: String,
        right_group_id: String,
        right_service_kind: String,
        right_index_range: String,
        right_pool_len: u8,
    },

    #[error(transparent)]
    #[api_error(id = "lan_ipv6.internal", status = 500)]
    Internal(#[from] LdError),
}
