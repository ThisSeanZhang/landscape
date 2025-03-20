use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::store::storev2::LandScapeStore;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirewallRuleConfig {
    // 优先级 用作存储主键
    pub index: u32,
    pub ip_protocol: u8,
    pub local_port: u16,
    pub address: IpAddr,
    pub prefixlen: u8,
}

impl LandScapeStore for FirewallRuleConfig {
    fn get_store_key(&self) -> String {
        self.index.to_string()
    }
}

#[repr(u8)]
pub enum LandscapeIpType {
    Ipv4 = 0,
    Ipv6 = 1,
}
