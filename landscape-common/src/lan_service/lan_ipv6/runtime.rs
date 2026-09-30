use std::collections::HashMap;
use std::net::Ipv6Addr;

use super::config::PrefixGroupServiceKind;
use crate::wan_service::ipv6_pd::LDIAPrefix;

#[derive(Debug, Clone)]
pub struct PdPrefixContext {
    pub expected_pd_len: u8,
    pub actual_prefix: Option<LDIAPrefix>,
}

pub type PdPrefixContextMap = HashMap<String, PdPrefixContext>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExpandedParentKey {
    Resolved(Ipv6Addr),
    PdFallback(String),
}

#[derive(Debug, Clone)]
pub struct ExpandedPrefixEntry {
    pub parent: ExpandedParentKey,
    pub parent_prefix_len: u8,
    pub service_kind: PrefixGroupServiceKind,
    pub start_index: u32,
    pub end_index: u32,
    pub pool_len: u8,
}
