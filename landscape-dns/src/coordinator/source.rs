use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use async_trait::async_trait;
use landscape_common::dns::{
    config::DnsUpstreamConfig,
    redirect::{DNSRedirectRule, DynamicDnsRedirectBatch},
    rule::DNSRuleConfig,
};

/// One flow's complete runtime input: rules plus the redirect and upstream
/// configs they resolve against.
#[derive(Debug, Clone)]
pub struct FlowConfigBundle {
    pub rules: Vec<DNSRuleConfig>,
    pub redirects: Vec<DNSRedirectRule>,
    pub dynamic_redirects: Vec<DynamicDnsRedirectBatch>,
    pub upstreams: Vec<DnsUpstreamConfig>,
}

/// Error returned by a [`DnsConfigSource`] when runtime config cannot be
/// loaded.
#[derive(Debug, Clone)]
pub struct DnsConfigError {
    message: String,
}

impl DnsConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for DnsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DnsConfigError {}

/// Port used by the DNS coordinator to load runtime configuration. The
/// application layer implements it over its database-backed config services;
/// `landscape-dns` never depends on the database.
#[async_trait]
pub trait DnsConfigSource: Send + Sync {
    async fn all_flow_rules(&self) -> Result<HashMap<u32, Vec<DNSRuleConfig>>, DnsConfigError>;

    async fn flow_rules(&self, flow_id: u32) -> Result<Vec<DNSRuleConfig>, DnsConfigError>;

    async fn flow_bundle(
        &self,
        flow_id: u32,
        rules: Vec<DNSRuleConfig>,
    ) -> Result<FlowConfigBundle, DnsConfigError>;

    async fn redirect_flow_ids(&self) -> Result<HashSet<u32>, DnsConfigError>;

    async fn dynamic_redirect_flow_ids(&self) -> Result<HashSet<u32>, DnsConfigError>;
}
