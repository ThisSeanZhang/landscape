use std::net::Ipv6Addr;

use serde::{Deserialize, Serialize};

use crate::net::MacAddr;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv6OfferInfo {
    pub boot_time: f64,
    pub relative_boot_time: u64,
    pub offered_addresses: Vec<DHCPv6AddressItem>,
    pub delegated_prefixes: Vec<DHCPv6PrefixItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv6AddressItem {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub duid: Option<String>,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub mac: Option<MacAddr>,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: Ipv6Addr,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub hostname: Option<String>,

    pub relative_active_time: u64,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub is_static: bool,

    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub prev_suffix: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv6PrefixItem {
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub duid: Option<String>,

    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub prefix: Ipv6Addr,
    pub prefix_len: u8,

    pub relative_active_time: u64,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}
