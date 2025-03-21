use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv6Addr};

use crate::{mark::PacketMark, store::storev2::LandScapeStore};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FirewallRuleConfig {
    // 优先级 用作存储主键
    pub index: u32,
    pub enable: bool,

    pub items: Vec<FirewallRuleItem>,
    /// 流量标记
    #[serde(default)]
    pub mark: PacketMark,
}

impl LandScapeStore for FirewallRuleConfig {
    fn get_store_key(&self) -> String {
        self.index.to_string()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirewallRuleItem {
    pub ip_protocol: u8,
    pub local_port: Option<u16>,
    pub address: IpAddr,
    pub ip_prefixlen: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LandscapeIpType {
    Ipv4 = 0,
    Ipv6 = 1,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirewallRuleMark {
    pub item: FirewallRuleItem,
    pub mark: PacketMark,
}
