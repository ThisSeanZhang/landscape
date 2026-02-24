use std::{collections::HashMap, net::Ipv6Addr};

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::net::MacAddr;

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ipv6_ra_server.d.ts")]
pub struct IPv6NAInfo {
    pub boot_time: f64,
    #[ts(type = "number")]
    #[cfg_attr(feature = "openapi", schema(value_type = HashMap<String, IPv6NAInfoItem>))]
    pub offered_ips: HashMap<Ipv6Addr, IPv6NAInfoItem>,
}

impl IPv6NAInfo {
    pub fn init() -> Self {
        IPv6NAInfo {
            boot_time: crate::utils::time::get_f64_timestamp(),
            offered_ips: HashMap::new(),
        }
    }

    pub fn clean_expired_entries(&mut self, threshold: u64) {
        self.offered_ips.retain(|_key, info_item| info_item.relative_active_time >= threshold);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, TS)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[ts(export, export_to = "common/ipv6_ra_server.d.ts")]
pub struct IPv6NAInfoItem {
    pub mac: MacAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: Ipv6Addr,
    /// Relative to the start time of RA
    #[ts(type = "number")]
    pub relative_active_time: u64,
    // valid_time in config, default is 600
    // pub expire_time: u32,
}

impl IPv6NAInfoItem {
    pub fn get_cache_key(&self) -> Ipv6Addr {
        // (self.mac.clone(), self.ip.clone())
        self.ip.clone()
    }
}
