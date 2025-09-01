use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::config::dns::{CloudflareMode, DnsUpstreamType, DomainConfig, FilterResult};
use crate::flow::mark::FlowMark;
use crate::flow::DnsRuntimeMarkInfo;

pub mod redirect;

#[derive(Debug, Clone)]
pub struct RuleHandlerInfo {
    pub rule_id: Option<Uuid>,
    pub flow_id: u32,
    pub resolver_id: Uuid,
    pub mark: DnsRuntimeMarkInfo,
    pub filter: FilterResult,
}

#[derive(Debug, Clone)]
pub struct RedirectInfo {
    pub result_ip: Vec<IpAddr>,
}

impl RuleHandlerInfo {
    pub fn mark(&self) -> &DnsRuntimeMarkInfo {
        &self.mark
    }

    pub fn filter_mode(&self) -> FilterResult {
        self.filter.clone()
    }
}

#[derive(Default, Clone, Debug)]
pub struct DnsServerInitInfo {
    pub rules: HashMap<DomainConfig, Arc<RuleHandlerInfo>>,
    pub redirect_rules: HashMap<DomainConfig, Arc<RedirectInfo>>,
    pub resolver_configs: Vec<DnsResolverConfig>,
    pub default_resolver: Option<RuleHandlerInfo>,
}

#[derive(Clone, Debug)]
pub struct DnsResolverConfig {
    pub id: Uuid,
    pub resolve_mode: DnsUpstreamMode,
    pub mark: FlowMark,
    pub flow_id: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "common/dns.d.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "snake_case")]
pub enum DnsUpstreamMode {
    Upstream { upstream: DnsUpstreamType, ips: Vec<IpAddr>, port: Option<u16> },
    Cloudflare { mode: CloudflareMode },
}

impl Default for DnsUpstreamMode {
    fn default() -> Self {
        DnsUpstreamMode::Cloudflare { mode: CloudflareMode::Tls }
    }
}
