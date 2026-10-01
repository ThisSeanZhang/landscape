use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use crate::net::MacAddr;

/// One ARP scan answer: the observed (ip, mac) pair. Feeds the LAN device
/// directory through `LanDiscoveryEvent`; per-device liveness lives in the
/// directory entries, so no round history is kept here anymore.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ArpScanInfoItem {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}
