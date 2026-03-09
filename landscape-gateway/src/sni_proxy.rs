use std::sync::atomic::{AtomicUsize, Ordering};

use landscape_common::config::gateway::{
    HttpUpstreamMatchRule, HttpUpstreamRuleConfig, HttpUpstreamTarget, LoadBalanceMethod,
};
use tokio::io;
use tokio::net::TcpStream;

use crate::SharedRules;

pub struct SniProxyRouter {
    rules: SharedRules,
    round_robin_counter: AtomicUsize,
}

impl SniProxyRouter {
    pub fn new(rules: SharedRules) -> Self {
        Self { rules, round_robin_counter: AtomicUsize::new(0) }
    }

    pub fn has_sni_proxy_rules(&self) -> bool {
        self.rules.load().iter().any(|rule| {
            rule.enable && matches!(rule.match_rule, HttpUpstreamMatchRule::SniProxy { .. })
        })
    }

    pub fn match_target(&self, sni: &str) -> Option<MatchedSniTarget> {
        let rules = self.rules.load();

        for rule in rules.iter() {
            if !rule.enable {
                continue;
            }

            if let HttpUpstreamMatchRule::SniProxy { domains } = &rule.match_rule {
                for domain in domains {
                    if domain.starts_with("*.") {
                        continue;
                    }
                    if domain.eq_ignore_ascii_case(sni) {
                        return MatchedSniTarget::new(rule, &self.round_robin_counter, sni);
                    }
                }
            }
        }

        for rule in rules.iter() {
            if !rule.enable {
                continue;
            }

            if let HttpUpstreamMatchRule::SniProxy { domains } = &rule.match_rule {
                for domain in domains {
                    if domain.starts_with("*.") && match_wildcard(domain, sni) {
                        return MatchedSniTarget::new(rule, &self.round_robin_counter, sni);
                    }
                }
            }
        }

        None
    }
}

#[derive(Debug, Clone)]
pub struct MatchedSniTarget {
    pub rule_name: String,
    pub sni: String,
    pub target: HttpUpstreamTarget,
}

impl MatchedSniTarget {
    fn new(rule: &HttpUpstreamRuleConfig, counter: &AtomicUsize, sni: &str) -> Option<Self> {
        let target =
            select_target(&rule.upstream.targets, &rule.upstream.load_balance, counter, sni)
                .cloned()?;

        Some(Self {
            rule_name: rule.name.clone(),
            sni: sni.to_string(),
            target,
        })
    }
}

pub async fn proxy_tls_passthrough(
    mut downstream: TcpStream,
    target: &MatchedSniTarget,
) -> io::Result<()> {
    let upstream_addr = format!("{}:{}", target.target.address, target.target.port);
    let mut upstream = TcpStream::connect(&upstream_addr).await?;

    let _ = io::copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

/// Parse the SNI (Server Name Indication) extension from a TLS ClientHello message.
///
/// The function peeks at the raw bytes without consuming them.
/// Returns `Some(hostname)` if a valid SNI extension is found, `None` otherwise.
pub fn parse_sni_from_client_hello(buf: &[u8]) -> Option<String> {
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len {
        return None;
    }

    let handshake = &buf[5..5 + record_len];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }

    let hs_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len() < 4 + hs_len {
        return None;
    }

    let ch = &handshake[4..4 + hs_len];
    if ch.len() < 34 {
        return None;
    }

    let mut pos = 34;

    if pos >= ch.len() {
        return None;
    }
    let session_id_len = ch[pos] as usize;
    pos += 1 + session_id_len;

    if pos + 2 > ch.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos >= ch.len() {
        return None;
    }
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;

    if pos + 2 > ch.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > ch.len() {
        return None;
    }

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_data_len > ext_end {
            return None;
        }

        if ext_type == 0x0000 {
            return parse_sni_extension(&ch[pos..pos + ext_data_len]);
        }
        pos += ext_data_len;
    }

    None
}

fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    let end = 2 + list_len;
    while pos + 3 <= end {
        let name_type = data[pos];
        let name_len = u16::from_be_bytes([data[pos + 1], data[pos + 2]]) as usize;
        pos += 3;
        if name_type == 0x00 && pos + name_len <= end {
            return String::from_utf8(data[pos..pos + name_len].to_vec())
                .ok()
                .map(|name| name.to_ascii_lowercase());
        }
        pos += name_len;
    }

    None
}

fn match_wildcard(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let suffix_lower = suffix.to_ascii_lowercase();
        let host_lower = host.to_ascii_lowercase();
        if host_lower.ends_with(&suffix_lower) {
            let prefix_len = host_lower.len() - suffix_lower.len();
            if prefix_len > 0 && host_lower.as_bytes()[prefix_len - 1] == b'.' {
                return true;
            }
        }
    }
    false
}

fn select_target<'a>(
    targets: &'a [HttpUpstreamTarget],
    method: &LoadBalanceMethod,
    counter: &AtomicUsize,
    sni: &str,
) -> Option<&'a HttpUpstreamTarget> {
    if targets.is_empty() {
        return None;
    }

    if targets.len() == 1 {
        return Some(&targets[0]);
    }

    match method {
        LoadBalanceMethod::RoundRobin => {
            let idx = counter.fetch_add(1, Ordering::Relaxed) % targets.len();
            Some(&targets[idx])
        }
        LoadBalanceMethod::Random => {
            let idx = fnv1a_hash(sni) % targets.len();
            Some(&targets[idx])
        }
        LoadBalanceMethod::Consistent => Some(weighted_select(targets, fnv1a_hash(sni))),
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

fn fnv1a_hash(input: &str) -> usize {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for b in input.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use std::sync::Arc;

    use landscape_common::config::gateway::HttpUpstreamConfig;

    fn target(address: &str, port: u16, weight: u32) -> HttpUpstreamTarget {
        HttpUpstreamTarget {
            address: address.to_string(),
            port,
            weight,
            tls: true,
        }
    }

    fn sni_rule(
        name: &str,
        domains: &[&str],
        targets: Vec<HttpUpstreamTarget>,
    ) -> HttpUpstreamRuleConfig {
        HttpUpstreamRuleConfig {
            id: uuid::Uuid::new_v4(),
            enable: true,
            name: name.to_string(),
            match_rule: HttpUpstreamMatchRule::SniProxy {
                domains: domains.iter().map(|d| d.to_string()).collect(),
            },
            upstream: HttpUpstreamConfig {
                targets,
                load_balance: LoadBalanceMethod::RoundRobin,
                health_check: None,
            },
            update_at: 0.0,
        }
    }

    fn shared_rules(rules: Vec<HttpUpstreamRuleConfig>) -> SharedRules {
        Arc::new(ArcSwap::new(Arc::new(rules)))
    }

    fn build_client_hello_with_sni(host: &str) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        let server_name_len = host_bytes.len() as u16;
        let sni_list_len = 1 + 2 + server_name_len;
        let sni_ext_len = 2 + sni_list_len;

        let mut hello = Vec::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&2u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(sni_ext_len + 4).to_be_bytes());
        hello.extend_from_slice(&0u16.to_be_bytes());
        hello.extend_from_slice(&sni_ext_len.to_be_bytes());
        hello.extend_from_slice(&sni_list_len.to_be_bytes());
        hello.push(0);
        hello.extend_from_slice(&server_name_len.to_be_bytes());
        hello.extend_from_slice(host_bytes);

        let hello_len = hello.len() as u32;
        let mut handshake = Vec::new();
        handshake.push(0x01);
        handshake.push(((hello_len >> 16) & 0xff) as u8);
        handshake.push(((hello_len >> 8) & 0xff) as u8);
        handshake.push((hello_len & 0xff) as u8);
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len() as u16;
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&record_len.to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn test_router_without_rules() {
        let router = SniProxyRouter::new(shared_rules(vec![]));
        assert!(!router.has_sni_proxy_rules());
        assert!(router.match_target("example.com").is_none());
    }

    #[test]
    fn test_parse_sni_from_valid_client_hello() {
        let hello = build_client_hello_with_sni("App.Example.com");
        assert_eq!(parse_sni_from_client_hello(&hello).as_deref(), Some("app.example.com"));
    }

    #[test]
    fn test_parse_sni_rejects_truncated_client_hello() {
        let mut hello = build_client_hello_with_sni("app.example.com");
        hello.truncate(hello.len() - 3);
        assert_eq!(parse_sni_from_client_hello(&hello), None);
    }

    #[test]
    fn test_exact_match_wins_over_wildcard() {
        let router = SniProxyRouter::new(shared_rules(vec![
            sni_rule("wildcard", &["*.example.com"], vec![target("10.0.0.2", 443, 1)]),
            sni_rule("exact", &["api.example.com"], vec![target("10.0.0.3", 8443, 1)]),
        ]));

        let matched = router.match_target("api.example.com").unwrap();
        assert_eq!(matched.rule_name, "exact");
        assert_eq!(matched.target.address, "10.0.0.3");
        assert_eq!(matched.target.port, 8443);
    }

    #[test]
    fn test_wildcard_match_requires_a_subdomain() {
        let router = SniProxyRouter::new(shared_rules(vec![sni_rule(
            "wildcard",
            &["*.example.com"],
            vec![target("10.0.0.2", 443, 1)],
        )]));

        assert!(router.match_target("api.example.com").is_some());
        assert!(router.match_target("example.com").is_none());
    }

    #[test]
    fn test_disabled_rules_are_ignored() {
        let mut rule = sni_rule("disabled", &["api.example.com"], vec![target("10.0.0.2", 443, 1)]);
        rule.enable = false;
        let router = SniProxyRouter::new(shared_rules(vec![rule]));

        assert!(!router.has_sni_proxy_rules());
        assert!(router.match_target("api.example.com").is_none());
    }

    #[test]
    fn test_round_robin_selects_multiple_targets() {
        let router = SniProxyRouter::new(shared_rules(vec![sni_rule(
            "rr",
            &["api.example.com"],
            vec![target("10.0.0.2", 443, 1), target("10.0.0.3", 443, 1)],
        )]));

        let first = router.match_target("api.example.com").unwrap();
        let second = router.match_target("api.example.com").unwrap();

        assert_eq!(first.target.address, "10.0.0.2");
        assert_eq!(second.target.address, "10.0.0.3");
    }

    #[test]
    fn test_rule_without_targets_is_not_selected() {
        let router = SniProxyRouter::new(shared_rules(vec![sni_rule(
            "empty",
            &["api.example.com"],
            vec![],
        )]));

        assert!(router.match_target("api.example.com").is_none());
    }
}
