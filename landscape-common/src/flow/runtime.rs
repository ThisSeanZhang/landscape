use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::flow::mark::FlowMark;
use crate::net::MacAddr;

use super::config::IpConfig;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResolvedFlowEntryRule {
    pub qos: Option<u32>,
    pub mode: ResolvedFlowEntryMatchMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ResolvedFlowEntryMatchMode {
    Mac { mac_addr: MacAddr },
    Ip { ip: IpAddr, prefix_len: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeFlowConfig {
    pub flow_id: u32,
    pub flow_match_rules: Vec<ResolvedFlowEntryRule>,
}

/// 用于 Flow ebpf DNS Map 记录操作
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowMarkInfo {
    pub ip: IpAddr,
    pub mark: u32,
    pub priority: u16,
}

#[derive(Debug, Clone)]
pub struct DnsRuntimeMarkInfo {
    pub mark: FlowMark,
    pub priority: u16,
}

/// IP 标记最小单元
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpMarkInfo {
    pub mark: FlowMark,
    pub cidr: IpConfig,
    // pub override_dns: bool,
    pub priority: u16,
}
