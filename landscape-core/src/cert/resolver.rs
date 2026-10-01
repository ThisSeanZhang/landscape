use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use arc_swap::ArcSwapOption;
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;

#[derive(Clone)]
pub(super) struct WildcardEntry {
    pub(super) suffix: String,
    pub(super) cert: Arc<CertifiedKey>,
}

#[derive(Clone, Default)]
pub(super) struct ResolverSnapshot {
    pub(super) exact: HashMap<String, Arc<CertifiedKey>>,
    pub(super) wildcards: Vec<WildcardEntry>,
    pub(super) fallback: Option<Arc<CertifiedKey>>,
}

impl ResolverSnapshot {
    pub(super) fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        if let Some(server_name) = server_name.and_then(normalize_domain_name) {
            if let Some(cert) = self.exact.get(&server_name) {
                return Some(cert.clone());
            }

            for wildcard in &self.wildcards {
                if wildcard_matches_host(&wildcard.suffix, &server_name) {
                    return Some(wildcard.cert.clone());
                }
            }
        }

        self.fallback.clone()
    }
}

pub(super) struct TlsResolverEntry {
    pub(super) cert_name: String,
    pub(super) configured_domains: Vec<String>,
    pub(super) cert_names: Vec<String>,
    pub(super) certified_key: CertifiedKey,
}

#[derive(Clone, Default)]
pub struct SharedSniResolver {
    inner: Arc<ArcSwapOption<ResolverSnapshot>>,
    advertised_domains: Arc<ArcSwap<Vec<String>>>,
}

impl fmt::Debug for SharedSniResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSniResolver").finish()
    }
}

impl SharedSniResolver {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwapOption::new(None)),
            advertised_domains: Arc::new(ArcSwap::from_pointee(Vec::new())),
        }
    }

    pub(super) fn swap(&self, snapshot: ResolverSnapshot) {
        let mut domains = snapshot.exact.keys().cloned().collect::<Vec<_>>();
        domains.sort();
        domains.dedup();
        self.advertised_domains.store(Arc::new(domains));
        self.inner.store(Some(Arc::new(snapshot)));
    }

    fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        self.inner.load_full().and_then(|snapshot| snapshot.resolve_name(server_name))
    }

    pub fn advertised_domains(&self) -> Vec<String> {
        self.advertised_domains.load().as_ref().clone()
    }

    pub fn advertised_domains_state(&self) -> Arc<ArcSwap<Vec<String>>> {
        self.advertised_domains.clone()
    }
}

impl ResolvesServerCert for SharedSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(client_hello.server_name())
    }
}

pub(super) fn build_resolver_snapshot_from_entries(
    entries: Vec<TlsResolverEntry>,
    fallback: Option<CertifiedKey>,
) -> (ResolverSnapshot, usize) {
    let mut snapshot = ResolverSnapshot {
        exact: HashMap::new(),
        wildcards: Vec::new(),
        fallback: fallback.map(Arc::new),
    };
    let mut exact_validator = ResolvesServerCertUsingSni::new();
    let mut wildcard_patterns = HashSet::new();
    let mut inserted_count = 0usize;

    for entry in entries {
        let cert = Arc::new(entry.certified_key);
        let cert_names: HashSet<String> = entry.cert_names.into_iter().collect();

        for domain in entry.configured_domains.into_iter().filter_map(|d| normalize_domain_name(&d))
        {
            if let Some(suffix) = wildcard_suffix(&domain) {
                if !cert_names.contains(&domain) {
                    tracing::warn!(
                        "Skip wildcard SNI mapping domain '{}' for cert '{}' (wildcard name not found in certificate SAN/CN)",
                        domain,
                        entry.cert_name
                    );
                    continue;
                }
                if !wildcard_patterns.insert(domain.clone()) {
                    continue;
                }
                snapshot.wildcards.push(WildcardEntry { suffix, cert: cert.clone() });
                inserted_count += 1;
                continue;
            }

            if snapshot.exact.contains_key(&domain) {
                continue;
            }
            if let Err(e) = exact_validator.add(&domain, (*cert).clone()) {
                tracing::warn!(
                    "Skip SNI mapping domain '{}' for cert '{}' ({})",
                    domain,
                    entry.cert_name,
                    e
                );
                continue;
            }
            snapshot.exact.insert(domain, cert.clone());
            inserted_count += 1;
        }
    }

    (snapshot, inserted_count)
}

pub(super) fn normalize_domain_name(domain: &str) -> Option<String> {
    let normalized = domain.trim().to_ascii_lowercase();
    if normalized.is_empty() { None } else { Some(normalized) }
}

fn wildcard_suffix(pattern: &str) -> Option<String> {
    let suffix = pattern.strip_prefix("*.")?;
    if suffix.is_empty() || suffix.contains('*') {
        return None;
    }
    Some(suffix.to_string())
}

fn wildcard_matches_host(suffix: &str, host: &str) -> bool {
    if host.len() <= suffix.len() + 1 || !host.ends_with(suffix) {
        return false;
    }

    let separator_index = host.len() - suffix.len() - 1;
    if host.as_bytes()[separator_index] != b'.' {
        return false;
    }

    let label = &host[..separator_index];
    !label.is_empty() && !label.contains('.')
}
