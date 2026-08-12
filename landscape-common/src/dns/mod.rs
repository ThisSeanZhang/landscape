use crate::dns::config::{DnsBindConfig, DnsUpstreamConfig};
use crate::dns::rule::{default_flow_id, DNSRuleConfig, FilterResult};
use crate::utils::id::gen_database_uuid;
use crate::utils::time::get_f64_timestamp;

pub mod check;
pub mod config;
pub mod dnr;
pub mod domain;
pub mod error;
pub mod provider_profile;
pub mod redirect;
pub mod rule;
pub mod runtime;
pub mod upstream;

pub use runtime::{CacheRuntimeConfig, DohRuntimeConfig, FlowDnsDependencies};

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
        bind_config: DnsBindConfig::default(),
    };
    (rule, upstream)
}
