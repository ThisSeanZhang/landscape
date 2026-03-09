use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use landscape_common::config::gateway::{
    HttpUpstreamMatchRule, HttpUpstreamRuleConfig, HttpUpstreamTarget, LoadBalanceMethod,
};
use pingora::http::RequestHeader;
use pingora::proxy::{ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;

use crate::SharedRules;

pub struct LandscapeReverseProxy {
    rules: SharedRules,
    round_robin_counter: AtomicUsize,
}

impl LandscapeReverseProxy {
    pub fn new(rules: SharedRules) -> Self {
        Self { rules, round_robin_counter: AtomicUsize::new(0) }
    }
}

pub struct ProxyCtx {
    pub matched_rule_name: Option<String>,
}

#[async_trait]
impl ProxyHttp for LandscapeReverseProxy {
    type CTX = ProxyCtx;

    fn new_ctx(&self) -> Self::CTX {
        ProxyCtx { matched_rule_name: None }
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let rules = self.rules.load();

        let req = session.req_header();
        let host = extract_host(req);
        let path = req.uri.path();

        // Phase 1: exact Host match + PathPrefix
        for rule in rules.iter() {
            if !rule.enable {
                continue;
            }
            match &rule.match_rule {
                HttpUpstreamMatchRule::Host { domains } => {
                    if let Some(h) = &host {
                        for domain in domains {
                            if domain.starts_with("*.") {
                                continue; // skip wildcards in first pass
                            }
                            if domain.eq_ignore_ascii_case(h) {
                                ctx.matched_rule_name = Some(rule.name.clone());
                                return make_peer(rule, &self.round_robin_counter, h, path);
                            }
                        }
                    }
                }
                HttpUpstreamMatchRule::PathPrefix { prefix } => {
                    if path.starts_with(prefix.as_str()) {
                        ctx.matched_rule_name = Some(rule.name.clone());
                        let h = host.as_deref().unwrap_or("");
                        return make_peer(rule, &self.round_robin_counter, h, path);
                    }
                }
                HttpUpstreamMatchRule::SniProxy { .. } => {
                    // SNI proxy rules handled by sni_proxy module, skip here
                    continue;
                }
            }
        }

        // Phase 2: wildcard Host match
        if let Some(h) = &host {
            for rule in rules.iter() {
                if !rule.enable {
                    continue;
                }
                if let HttpUpstreamMatchRule::Host { domains } = &rule.match_rule {
                    for domain in domains {
                        if domain.starts_with("*.") && match_wildcard(domain, h) {
                            ctx.matched_rule_name = Some(rule.name.clone());
                            return make_peer(rule, &self.round_robin_counter, h, path);
                        }
                    }
                }
            }
        }

        Err(pingora::Error::new_str("No matching upstream rule found"))
    }
}

fn extract_host(req: &RequestHeader) -> Option<String> {
    // Try Host header first
    if let Some(host) = req.headers.get("host") {
        if let Ok(h) = host.to_str() {
            // Strip port if present
            let h = h.split(':').next().unwrap_or(h);
            return Some(h.to_ascii_lowercase());
        }
    }
    // Fallback to URI authority
    if let Some(authority) = req.uri.authority() {
        let h = authority.host();
        return Some(h.to_ascii_lowercase());
    }
    None
}

fn match_wildcard(pattern: &str, host: &str) -> bool {
    // pattern: "*.example.com" matches "foo.example.com"
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix_lower = suffix.to_ascii_lowercase();
        let host_lower = host.to_ascii_lowercase();
        if host_lower.ends_with(&suffix_lower) {
            let prefix_len = host_lower.len() - suffix_lower.len();
            // Must have at least one char before the suffix, and it must end with '.'
            if prefix_len > 0 && host_lower.as_bytes()[prefix_len - 1] == b'.' {
                return true;
            }
        }
    }
    false
}

fn make_peer(
    rule: &HttpUpstreamRuleConfig,
    counter: &AtomicUsize,
    host: &str,
    path: &str,
) -> pingora::Result<Box<HttpPeer>> {
    let targets = &rule.upstream.targets;
    if targets.is_empty() {
        return Err(pingora::Error::new_str("No upstream targets configured"));
    }

    let target = select_target(targets, &rule.upstream.load_balance, counter, host, path);
    let mut peer =
        HttpPeer::new((target.address.as_str(), target.port), target.tls, target.address.clone());
    peer.options.connection_timeout = Some(std::time::Duration::from_secs(10));
    Ok(Box::new(peer))
}

fn select_target<'a>(
    targets: &'a [HttpUpstreamTarget],
    method: &LoadBalanceMethod,
    counter: &AtomicUsize,
    host: &str,
    path: &str,
) -> &'a HttpUpstreamTarget {
    if targets.len() == 1 {
        return &targets[0];
    }

    match method {
        LoadBalanceMethod::RoundRobin => {
            let idx = counter.fetch_add(1, Ordering::Relaxed) % targets.len();
            &targets[idx]
        }
        LoadBalanceMethod::Random => {
            let idx = fnv1a_hash(host, path) % targets.len();
            &targets[idx]
        }
        LoadBalanceMethod::Consistent => {
            // Weighted consistent hashing by host
            weighted_select(targets, fnv1a_hash(host, ""))
        }
    }
}

fn weighted_select(targets: &[HttpUpstreamTarget], seed: usize) -> &HttpUpstreamTarget {
    let total_weight: u32 = targets.iter().map(|t| t.weight).sum();
    if total_weight == 0 {
        return &targets[0];
    }
    let pick = (seed as u32) % total_weight;
    let mut acc = 0u32;
    for target in targets {
        acc += target.weight;
        if pick < acc {
            return target;
        }
    }
    targets.last().unwrap()
}

fn fnv1a_hash(host: &str, path: &str) -> usize {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for b in host.bytes().chain(path.bytes()) {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash as usize
}
