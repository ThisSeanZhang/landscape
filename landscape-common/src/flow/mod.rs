use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::store::storev2::LandScapeStore;

pub mod mark;
pub mod target;

/// 流控配置结构体
#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[ts(export, export_to = "flow.ts")]
pub struct FlowConfig {
    /// 是否启用
    pub enable: bool,
    /// 流 ID
    pub flow_id: u32,
    /// 匹配规则
    pub flow_match_rules: Vec<PacketMatchMark>,
    /// 处理流量目标网卡, 目前只取第一个
    /// 暂定, 可能会移动到具体的网卡上进行设置
    pub packet_handle_iface_name: Vec<FlowTarget>,
    /// 备注
    pub remark: String,
}

impl LandScapeStore for FlowConfig {
    fn get_store_key(&self) -> String {
        self.flow_id.to_string()
    }
}

/// 数据包匹配该流控标志
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, TS)]
#[ts(export, export_to = "flow.ts")]
pub struct PacketMatchMark {
    pub ip: IpAddr,
    pub vlan_id: Option<u32>,
    pub qos: Option<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, TS)]
#[ts(export, export_to = "flow.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
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
