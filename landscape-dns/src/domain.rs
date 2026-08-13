use std::sync::{Arc, OnceLock};

use hickory_proto::rr::Name;
use landscape_common::dns::error::DnsError;

/// Canonical per-request representation of a DNS name. Parsed once per query
/// and shared unchanged across the whole resolution chain (local resolver,
/// redirect engine, resolve engine, cache), so no stage re-normalizes or
/// re-copies the name.
pub struct ParsedDomain {
    /// FQDN with trailing dot, lowercase.
    raw: Arc<str>,
    /// Normalized name: lowercase, no trailing dot.
    name: String,
    labels: Vec<String>,
    dns_name: Name,
    /// `name` reversed, for allocation-free trie matching. Computed lazily:
    /// only matchers with subdomain rules ever need it.
    reversed: OnceLock<String>,
}

impl ParsedDomain {
    pub fn new(fqdn: &str) -> Result<Self, DnsError> {
        let name = fqdn.strip_suffix('.').unwrap_or(fqdn).to_ascii_lowercase();
        let labels: Vec<String> = name.split('.').map(String::from).collect();
        let dns_name =
            Name::from_utf8(&name).map_err(|_| DnsError::Invalid { domain: fqdn.to_string() })?;
        let raw = Arc::from(format!("{}.", name).as_str());
        Ok(Self {
            raw,
            name,
            labels,
            dns_name,
            reversed: OnceLock::new(),
        })
    }

    pub fn as_dns_name(&self) -> &Name {
        &self.dns_name
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The raw FQDN as the cache key domain: cloning is a refcount bump, no
    /// heap allocation.
    pub fn raw_arc(&self) -> &Arc<str> {
        &self.raw
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn reversed(&self) -> &str {
        self.reversed.get_or_init(|| self.name.chars().rev().collect())
    }

    pub fn tld(&self) -> &str {
        self.labels.last().map(|s| s.as_str()).unwrap_or(&self.name)
    }

    pub fn arpa_sld(&self) -> Option<&str> {
        if self.labels.len() >= 2 && self.labels.last().map(|s| s.as_str()) == Some("arpa") {
            Some(&self.labels[self.labels.len() - 2])
        } else {
            None
        }
    }

    pub fn arpa_prefix(&self) -> Option<&str> {
        self.name.strip_suffix(".arpa")
    }

    pub fn hostname_for_tld(&self, tld: &str) -> Option<&str> {
        let suffix = format!(".{}", tld);
        self.name.strip_suffix(&suffix).filter(|h| !h.is_empty())
    }
}
