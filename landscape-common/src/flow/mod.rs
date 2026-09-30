use std::net::IpAddr;

use crate::flow::mark::FlowMark;
use crate::net::MacAddr;

pub mod config;
pub mod dataplane;
pub mod dns_result_sink;
pub mod error;
pub mod flow_socket_registrar;
pub mod ip_mark;
pub mod mark;
pub mod service;
pub mod target;
pub mod trace;

pub use config::*;
pub use dns_result_sink::{DnsResultSink, NoopDnsResultSink};
pub use error::{DstIpRuleError, FlowRuleError};
pub use flow_socket_registrar::{FlowSocketRegistrar, NoopFlowSocketRegistrar};

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
