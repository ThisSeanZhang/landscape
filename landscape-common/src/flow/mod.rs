use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{net::MacAddr, store::storev2::LandScapeStore};

/// 流控配置结构体
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FlowConfig {
    /// 是否启用
    pub enable: bool,
    /// 流 ID
    pub flow_id: u32,
    /// 匹配规则
    pub flow_match_rules: Vec<PacketMatchMark>,
    /// 处理流量目标网卡, 目前只取第一个
    pub packet_handle_iface_name: Vec<FlowTarget>,
}

impl LandScapeStore for FlowConfig {
    fn get_store_key(&self) -> String {
        self.flow_id.to_string()
    }
}

/// 数据包匹配该流控标志
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct PacketMatchMark {
    pub mac: MacAddr,
    pub vlan_id: Option<u32>,
    pub qos: Option<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
pub struct FlowDnsMarkInfo {
    pub ip: IpAddr,
    pub mark: u32,
}
