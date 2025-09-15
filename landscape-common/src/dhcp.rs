use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::net::MacAddr;

#[derive(Debug, Serialize, Deserialize, Clone, Default, TS)]
#[ts(export, export_to = "common/dhcp_v4_server.d.ts")]
pub struct DHCPv4OfferInfo {
    pub boot_time: f64,
    #[ts(type = "number")]
    pub relative_boot_time: u64,
    pub offered_ips: Vec<DHCPv4OfferInfoItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[ts(export, export_to = "common/dhcp_v4_server.d.ts")]
pub struct DHCPv4OfferInfoItem {
    pub mac: MacAddr,
    pub ip: Ipv4Addr,
    #[ts(type = "number")]
    pub relative_active_time: u64,
    pub expire_time: u32,
    pub is_static: bool,
}
