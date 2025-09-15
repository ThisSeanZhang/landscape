use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use uuid::Uuid;

use crate::config::dns::{
    default_flow_id, DNSRuleConfig, DNSRuntimeRule, DomainConfig, FilterResult,
};
use crate::dns::config::DnsUpstreamConfig;
use crate::dns::redirect::DNSRedirectRuntimeRule;
use crate::flow::mark::FlowMark;
use crate::flow::DnsRuntimeMarkInfo;
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

pub mod config;
pub mod redirect;
pub mod upstream;

#[derive(Default, Debug)]
pub struct ChainDnsServerInitInfo {
    pub dns_rules: Vec<DNSRuntimeRule>,
    pub redirect_rules: Vec<DNSRedirectRuntimeRule>,
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
    pub resolve_mode: DnsUpstreamConfig,
    pub mark: FlowMark,
    pub flow_id: u32,
}

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
        flow_id: default_flow_id(),
        update_at: get_f64_timestamp(),
        upstream_id: upstream.id,
    };
    (rule, upstream)
}
