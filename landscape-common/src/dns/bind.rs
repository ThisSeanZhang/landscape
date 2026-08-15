use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Source-address binding for connections to a DNS upstream. Optional: when
/// both addresses are `None` sockets bind to the OS-chosen source address.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DnsBindConfig {
    /// Source address for IPv4 connections to the upstream (optional)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr4: Option<Ipv4Addr>,
    /// Source address for IPv6 connections to the upstream (optional)
    #[serde(default)]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false, value_type = String))]
    pub bind_addr6: Option<Ipv6Addr>,
}
