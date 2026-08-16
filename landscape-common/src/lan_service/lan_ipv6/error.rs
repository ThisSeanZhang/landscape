use std::fmt;

use serde::Serialize;

use landscape_macro::LdApiError;

use crate::database::error::DbError;

#[derive(Debug, Serialize)]
pub struct WanReservedPrefixConflictDetails {
    pub iface_name: String,
    pub group_id: String,
    pub service_kind: String,
    pub index_range: String,
    pub pool_len: u8,
}

impl fmt::Display for WanReservedPrefixConflictDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LAN IPv6 prefix conflict: iface={}, group={}, {} index={} pool_len=/{} overlaps WAN-reserved /64 slot 0",
            self.iface_name, self.group_id, self.service_kind, self.index_range, self.pool_len
        )
    }
}

#[derive(Debug, Serialize)]
pub struct PrefixSlotOverlapDetails {
    pub slot_range: String,
    pub left_iface_name: String,
    pub left_group_id: String,
    pub left_service_kind: String,
    pub left_index_range: String,
    pub left_pool_len: u8,
    pub right_iface_name: String,
    pub right_group_id: String,
    pub right_service_kind: String,
    pub right_index_range: String,
    pub right_pool_len: u8,
}

impl fmt::Display for PrefixSlotOverlapDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LAN IPv6 prefix conflict at /64 slot range {}: iface={}, group={}, {} index={} pool_len=/{} overlaps iface={}, group={}, {} index={} pool_len=/{}",
            self.slot_range,
            self.left_iface_name,
            self.left_group_id,
            self.left_service_kind,
            self.left_index_range,
            self.left_pool_len,
            self.right_iface_name,
            self.right_group_id,
            self.right_service_kind,
            self.right_index_range,
            self.right_pool_len
        )
    }
}

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum LanIPv6Error {
    #[error("LAN IPv6 configuration has been modified. Please refresh and try again.")]
    #[api_error(id = "lan_ipv6.config_conflict", status = 409)]
    ConfigConflict,

    #[error("{0}")]
    #[api_error(id = "lan_ipv6.prefix_conflict.wan_reserved", status = 409, serialize)]
    WanReservedPrefixConflict(Box<WanReservedPrefixConflictDetails>),

    #[error("{0}")]
    #[api_error(id = "lan_ipv6.prefix_conflict.overlap", status = 409, serialize)]
    PrefixSlotOverlap(Box<PrefixSlotOverlapDetails>),

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
}
