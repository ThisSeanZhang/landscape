use std::{collections::VecDeque, net::Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::{net::MacAddr, LAND_ARP_INFO_SIZE};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv4OfferInfo {
    pub boot_time: f64,
    pub relative_boot_time: u64,
    pub offered_ips: Vec<DHCPv4OfferInfoItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DHCPv4OfferInfoItem {
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub hostname: Option<String>,
    pub mac: MacAddr,
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: Ipv4Addr,
    pub relative_active_time: u64,
    pub expire_time: u32,
    pub is_static: bool,
}

pub struct ArpScanStatus {
    infos: VecDeque<ArpScanInfo>,
}

impl ArpScanStatus {
    pub fn new() -> Self {
        Self { infos: VecDeque::with_capacity(LAND_ARP_INFO_SIZE) }
    }

    pub fn insert_new_info(&mut self, value: ArpScanInfo) {
        if self.infos.len() == LAND_ARP_INFO_SIZE {
            self.infos.pop_front();
        }

        self.infos.push_back(value);
    }

    pub fn get_arp_info(&self) -> Vec<ArpScanInfo> {
        self.infos.iter().cloned().collect()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ArpScanInfo {
    infos: Vec<ArpScanInfoItem>,
}

impl ArpScanInfo {
    pub fn new(infos: Vec<ArpScanInfoItem>) -> Self {
        Self { infos }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ArpScanInfoItem {
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
}
