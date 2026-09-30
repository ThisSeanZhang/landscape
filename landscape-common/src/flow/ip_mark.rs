use serde::{Deserialize, Serialize};

use crate::flow::mark::FlowMark;

pub use super::config::{IpConfig, WanIPRuleSource, WanIpRuleConfig};
pub use super::error::DstIpRuleError;

/// IP 标记最小单元
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpMarkInfo {
    pub mark: FlowMark,
    pub cidr: IpConfig,
    // pub override_dns: bool,
    pub priority: u16,
}
