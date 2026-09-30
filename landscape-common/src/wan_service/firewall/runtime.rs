use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::flow::mark::FlowMark;
use crate::network::LandscapeIpProtocolCode;

/// 存入 bpf map 中的遍历项
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirewallRuleItem {
    pub ip_protocol: Option<LandscapeIpProtocolCode>,
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
    pub mark: FlowMark,
}
