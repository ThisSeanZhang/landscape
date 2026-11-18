//! Immutable routing state prepared before a rule update is published.
//!
//! A single snapshot contains HTTP and SNI routes. Request handlers only match
//! compiled routes and choose an upstream; they never interpret stored config.

use std::collections::HashSet;
use std::sync::Arc;

use http::{HeaderName, HeaderValue};
use landscape_common::sys_service::gateway::{
    ClientIpHeaderPolicy, GatewayError, HttpUpstreamConfig, HttpUpstreamMatchRule,
    HttpUpstreamRuleConfig, HttpUpstreamTarget, LoadBalanceMethod, PathRewriteMode,
    ProxyHeaderConflictMode,
};

#[derive(Debug, Default)]
pub struct CompiledGatewayRoutes {
    rule_count: usize,
    hosts: Vec<CompiledHostRule>,
    legacy: Vec<CompiledLegacyRule>,
    sni: Vec<(CompiledDomains, Arc<CompiledSniRoute>)>,
}

#[derive(Debug)]
struct CompiledDomains {
    exact: Vec<String>,
    wildcard_suffixes: Vec<String>,
}

impl CompiledDomains {
    fn new(domains: &[String]) -> Self {
        let mut exact = Vec::new();
        let mut wildcard_suffixes = Vec::new();
        for domain in domains {
            let domain = normalize_domain(domain);
            if let Some(suffix) = domain.strip_prefix("*.") {
                wildcard_suffixes.push(format!(".{suffix}"));
            } else if !domain.is_empty() {
                exact.push(domain);
            }
        }
        Self { exact, wildcard_suffixes }
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.wildcard_suffixes.is_empty()
    }

    fn matches(&self, host: &str, wildcard: bool) -> bool {
        if wildcard {
            self.wildcard_suffixes.iter().any(|suffix| host.ends_with(suffix))
        } else {
            self.exact.iter().any(|domain| domain == host)
        }
    }
}

#[derive(Debug)]
struct CompiledHostRule {
    domains: CompiledDomains,
    default: Arc<CompiledHttpRoute>,
    paths: Vec<Arc<CompiledHttpRoute>>,
}

#[derive(Debug)]
struct CompiledLegacyRule {
    domains: CompiledDomains,
    prefix: String,
    route: Arc<CompiledHttpRoute>,
}

#[derive(Debug)]
pub(crate) struct CompiledHttpRoute {
    pub rule_name: String,
    pub upstream: CompiledUpstream,
    pub rewrite_mode: PathRewriteMode,
    pub matched_prefix: Option<String>,
}

#[derive(Debug)]
pub(crate) struct CompiledSniRoute {
    pub rule_name: String,
    pub upstream: CompiledUpstream,
}

#[derive(Debug)]
pub(crate) struct CompiledUpstream {
    pub targets: Vec<HttpUpstreamTarget>,
    pub load_balance: LoadBalanceMethod,
    pub request_headers: Vec<CompiledRequestHeader>,
    pub header_conflict_mode: ProxyHeaderConflictMode,
    pub client_ip_headers: ClientIpHeaderPolicy,
}

#[derive(Debug)]
pub(crate) struct CompiledRequestHeader {
    pub name: HeaderName,
    pub value: HeaderValue,
}

impl CompiledUpstream {
    fn compile(upstream: &HttpUpstreamConfig) -> Result<Self, GatewayError> {
        let request_headers = upstream
            .request_headers
            .iter()
            .map(|header| {
                let name = HeaderName::from_bytes(header.name.as_bytes())
                    .map_err(|_| GatewayError::InvalidHeaderName { name: header.name.clone() })?;
                let value = HeaderValue::from_str(&header.value)
                    .map_err(|_| GatewayError::InvalidHeaderValue { name: header.name.clone() })?;
                Ok(CompiledRequestHeader { name, value })
            })
            .collect::<Result<Vec<_>, GatewayError>>()?;
        Ok(Self {
            targets: upstream.targets.clone(),
            load_balance: upstream.load_balance.clone(),
            request_headers,
            header_conflict_mode: upstream.header_conflict_mode.clone(),
            client_ip_headers: upstream.client_ip_headers.clone(),
        })
    }
}

impl CompiledGatewayRoutes {
    /// Prepare the whole candidate without changing the active snapshot.
    /// Disabled rules are checked too, but do not participate in matching.
    pub fn compile(rules: &[HttpUpstreamRuleConfig]) -> Result<Self, GatewayError> {
        let mut compiled = Self { rule_count: rules.len(), ..Self::default() };
        for rule in rules {
            let domains = CompiledDomains::new(&rule.domains);
            let upstream = CompiledUpstream::compile(&rule.upstream)?;
            if domains.is_empty()
                && (!rule.domains.is_empty()
                    || !matches!(rule.match_rule, HttpUpstreamMatchRule::LegacyPathPrefix { .. }))
            {
                return Err(GatewayError::DomainsRequired { rule_name: rule.name.clone() });
            }
            match &rule.match_rule {
                HttpUpstreamMatchRule::Host { path_groups } => {
                    let default = Arc::new(CompiledHttpRoute {
                        rule_name: rule.name.clone(),
                        upstream,
                        rewrite_mode: PathRewriteMode::Preserve,
                        matched_prefix: None,
                    });
                    let mut seen = HashSet::new();
                    let mut paths = Vec::with_capacity(path_groups.len());
                    for group in path_groups {
                        let prefix = normalize_prefix(&group.prefix)?;
                        if !seen.insert(prefix.clone()) {
                            return Err(GatewayError::DuplicatePathGroupPrefix {
                                prefix: group.prefix.clone(),
                                rule_name: rule.name.clone(),
                            });
                        }
                        paths.push(Arc::new(CompiledHttpRoute {
                            rule_name: rule.name.clone(),
                            upstream: CompiledUpstream::compile(&group.upstream)?,
                            rewrite_mode: group.rewrite_mode.clone(),
                            matched_prefix: Some(prefix),
                        }));
                    }
                    if rule.enable {
                        compiled.hosts.push(CompiledHostRule { domains, default, paths });
                    }
                }
                HttpUpstreamMatchRule::SniProxy => {
                    if rule.enable {
                        compiled.sni.push((
                            domains,
                            Arc::new(CompiledSniRoute { rule_name: rule.name.clone(), upstream }),
                        ));
                    }
                }
                HttpUpstreamMatchRule::LegacyPathPrefix { prefix } => {
                    let prefix = normalize_prefix(prefix)?;
                    if rule.enable {
                        compiled.legacy.push(CompiledLegacyRule {
                            domains,
                            prefix,
                            route: Arc::new(CompiledHttpRoute {
                                rule_name: rule.name.clone(),
                                upstream,
                                rewrite_mode: PathRewriteMode::Preserve,
                                matched_prefix: None,
                            }),
                        });
                    }
                }
            }
        }
        Ok(compiled)
    }

    /// Number of source rules, including disabled rules.
    pub fn len(&self) -> usize {
        self.rule_count
    }

    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }

    pub(crate) fn match_http_route(
        &self,
        host: Option<&str>,
        path: &str,
    ) -> Option<Arc<CompiledHttpRoute>> {
        if let Some(host) = host {
            let host = normalize_domain(host);
            for wildcard in [false, true] {
                if let Some(rule) =
                    self.hosts.iter().find(|rule| rule.domains.matches(&host, wildcard))
                {
                    let route = rule
                        .paths
                        .iter()
                        .filter(|route| {
                            path_matches_prefix(path, route.matched_prefix.as_deref().unwrap())
                        })
                        .max_by_key(|route| route.matched_prefix.as_ref().unwrap().len())
                        .unwrap_or(&rule.default);
                    return Some(route.clone());
                }
            }
            for wildcard in [false, true] {
                if let Some(rule) = self.legacy.iter().find(|rule| {
                    rule.domains.matches(&host, wildcard) && path_matches_prefix(path, &rule.prefix)
                }) {
                    return Some(rule.route.clone());
                }
            }
        }
        self.legacy
            .iter()
            .find(|rule| rule.domains.is_empty() && path_matches_prefix(path, &rule.prefix))
            .map(|rule| rule.route.clone())
    }

    pub(crate) fn has_sni_routes(&self) -> bool {
        !self.sni.is_empty()
    }

    pub(crate) fn match_sni_route(&self, sni: &str) -> Option<Arc<CompiledSniRoute>> {
        let sni = normalize_domain(sni);
        for wildcard in [false, true] {
            if let Some((_, route)) =
                self.sni.iter().find(|(domains, _)| domains.matches(&sni, wildcard))
            {
                return Some(route.clone());
            }
        }
        None
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_prefix(prefix: &str) -> Result<String, GatewayError> {
    let trimmed = prefix.trim();
    if !trimmed.starts_with('/') {
        return Err(GatewayError::InvalidPathPrefix { prefix: prefix.to_string() });
    }
    let normalized = trimmed.trim_end_matches('/');
    Ok(if normalized.is_empty() { "/".to_string() } else { normalized.to_string() })
}

/// `prefix` has already been normalized during compilation.
pub(crate) fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path.strip_prefix(prefix).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}
