use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use ts_rs::TS;
use uuid::Uuid;

use crate::config::dns::{
    default_flow_id, CloudflareMode, DNSResolveMode, DNSRuleConfig, DNSRuntimeRule,
    DnsUpstreamType, DomainConfig, FilterResult,
};
use crate::dns::redirect::DNSRedirectRuntimeRule;
use crate::dns::upstream::DnsUpstreamConfig;
use crate::flow::mark::FlowMark;
use crate::flow::DnsRuntimeMarkInfo;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

pub mod redirect;
pub mod upstream;

#[derive(Debug, Clone)]
pub struct RuleHandlerInfo {
    pub rule_id: Uuid,
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

#[derive(Default, Debug)]
pub struct ChainDnsServerInitInfo {
    pub dns_rules: Vec<DNSRuntimeRule>,
    pub redirect_rules: Vec<DNSRedirectRuntimeRule>,
}

#[deprecated]
#[derive(Default, Clone, Debug)]
pub struct DnsServerInitInfo {
    pub rules: HashMap<DomainConfig, Arc<RuleHandlerInfo>>,
    pub redirect_rules: HashMap<DomainConfig, Arc<RedirectInfo>>,
    pub resolver_configs: Vec<DnsResolverConfig>,
    pub default_resolver: Option<RuleHandlerInfo>,
}

#[deprecated]
#[derive(Clone, Debug)]
pub struct DnsResolverConfig {
    pub id: Uuid,
    pub resolve_mode: DnsUpstreamMode,
    pub mark: FlowMark,
    pub flow_id: u32,
}

#[deprecated]
#[derive(Serialize, Deserialize, Debug, Clone, TS)]
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

pub fn gen_default_dns_rule_and_upstream() -> (DNSRuleConfig, DnsUpstreamConfig) {
    let upstream = DnsUpstreamConfig::default();
    let rule = DNSRuleConfig {
        id: gen_database_uuid(),
        name: "Landscape Router default rule".into(),
        index: 10000,
        enable: true,
        filter: FilterResult::default(),
        mark: Default::default(),
        source: vec![],
        resolve_mode: DNSResolveMode::default(),
        flow_id: default_flow_id(),
        update_at: get_f64_timestamp(),
        upstream_id: upstream.id,
    };
    (rule, upstream)
}
