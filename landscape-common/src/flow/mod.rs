use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::flow::mark::FlowMark;

pub mod config;
pub mod mark;
pub mod target;

/// 数据包匹配该流控标志
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, TS)]
#[ts(export, export_to = "common/flow.d.ts")]
pub struct PacketMatchMark {
    pub ip: IpAddr,
    pub vlan_id: Option<u32>,
    pub qos: Option<u8>,
    #[serde(default = "default_prefix_len")]
    pub prefix_len: u8,
}

fn default_prefix_len() -> u8 {
    32
}

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[ts(export, export_to = "common/flow.d.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum FlowTarget {
    Interface { name: String },
    Netns { container_name: String },
}

/// 用于 Flow ebpf 匹配记录操作
pub struct FlowMathPair {
    pub match_rule: PacketMatchMark,
    pub flow_id: u32,
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
