use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::{flow::mark::FlowDnsMark, store::storev2::LandScapeStore};

/// DNS 配置
#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "dns.ts")]
pub struct DNSRuleConfig {
    pub name: String,
    /// 优先级
    pub index: u32,
    /// 是否启用
    pub enable: bool,
    /// 过滤模式
    #[serde(default)]
    pub filter: FilterResult,
    /// 解析模式
    pub resolve_mode: DNSResolveMode,
    /// 流量标记
    #[serde(default)]
    pub mark: FlowDnsMark,
    /// 匹配规则列表
    #[serde(default)]
    pub source: Vec<RuleSource>,

    #[serde(default = "default_flow_id")]
    pub flow_id: u32,
}

fn default_flow_id() -> u32 {
    0_u32
}

impl LandScapeStore for DNSRuleConfig {
    fn get_store_key(&self) -> String {
        self.index.to_string()
    }
}

impl Default for DNSRuleConfig {
    fn default() -> Self {
        Self {
            name: "Landscape Router default rule".into(),
            index: 10000,
            enable: true,
            filter: FilterResult::default(),
            mark: Default::default(),
            source: vec![],
            resolve_mode: DNSResolveMode::default(),
            flow_id: default_flow_id(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "dns.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    GeoKey { key: String },
    Config(DomainConfig),
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "dns.ts")]
pub struct DomainConfig {
    pub match_type: DomainMatchType,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "dns.ts")]
#[serde(rename_all = "lowercase")]
pub enum DomainMatchType {
    /// The value is used as is.
    Plain = 0,
    /// The value is used as a regular expression.
    Regex = 1,
    /// 域名匹配， 前缀匹配
    Domain = 2,
    /// The value is a domain.
    Full = 3,
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "dns.ts")]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum DNSResolveMode {
    Redirect { ips: Vec<IpAddr> },
    Upstream { upstream: DnsUpstreamType, ips: Vec<IpAddr>, port: Option<u16> },
    CloudFlare { mode: CloudFlareMode },
}

impl Default for DNSResolveMode {
    fn default() -> Self {
        DNSResolveMode::CloudFlare { mode: CloudFlareMode::Https }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, TS)]
#[ts(export, export_to = "dns.ts")]
#[serde(rename_all = "lowercase")]
#[serde(tag = "t")]
pub enum DnsUpstreamType {
    #[default]
    Plaintext, // 传统 DNS（UDP/TCP，无加密）
    Tls {
        domain: String,
    }, // DNS over TLS (DoT)
    Https {
        domain: String,
    }, // DNS over HTTPS (DoH)
}

#[derive(Serialize, Deserialize, Debug, Clone, TS)]
#[ts(export, export_to = "dns.ts")]
#[serde(rename_all = "lowercase")]
pub enum CloudFlareMode {
    Plaintext, // 1.1.1.1 (UDP/TCP)
    Tls,       // tls://1.1.1.1
    Https,     // https://cloudflare-dns.com/dns-query
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, TS)]
#[ts(export, export_to = "dns.ts")]
#[serde(rename_all = "lowercase")]
pub enum FilterResult {
    #[default]
    Unfilter,
    OnlyIPv4,
    OnlyIPv6,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::DNSResolveMode;

    #[test]
    fn test_serde() {
        let value = DNSResolveMode::Upstream {
            upstream: super::DnsUpstreamType::Https { domain: "cloudflare-dns.com".to_string() },
            ips: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            port: Some(443),
        };
        let result = serde_json::to_string(&value).unwrap();
        println!("{result}");
    }
}
