use std::{borrow::Cow, sync::Arc};

use hickory_proto::rr::Name;
use landscape_common::dns::error::DnsServiceError;

/// Normalize user-provided domain text without forcing an allocation in the
/// common case: trim trailing dots and lowercase only when uppercase bytes are
/// present. `Cow` is used so already-normalized input can be borrowed directly.
pub(crate) fn normalize_domain_text(domain: &str) -> Cow<'_, str> {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.as_bytes().iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

/// Canonical per-request representation of a DNS name. Parsed once per query
/// and shared unchanged across the whole resolution chain (local resolver,
/// redirect engine, resolve engine, cache), so no stage re-normalizes or
/// re-copies the name.
pub struct ParsedDomain {
    /// FQDN with trailing dot, lowercase ASCII/Punycode.
    raw: Arc<str>,
    /// Normalized name: lowercase ASCII/Punycode, no trailing dot.
    name: String,
    labels: Vec<String>,
    dns_name: Name,
}

impl ParsedDomain {
    pub fn new(fqdn: &str) -> Result<Self, DnsServiceError> {
        let normalized = normalize_domain_text(fqdn);
        let dns_name = Name::from_utf8(normalized.as_ref())
            .map_err(|_| DnsServiceError::Invalid { domain: fqdn.to_string() })?;
        // Hickory parses Unicode labels as IDNA and stores their ASCII/Punycode
        // form. Keep that canonical representation everywhere downstream so
        // byte-oriented matchers and suffix checks never see UTF-8 labels.
        let name = dns_name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<String> = name.split('.').map(String::from).collect();
        let raw = Arc::from(format!("{}.", name).as_str());
        Ok(Self { raw, name, labels, dns_name })
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

#[cfg(test)]
mod tests {
    use super::ParsedDomain;

    #[test]
    fn canonicalizes_unicode_labels_to_ascii_punycode() {
        let domain = ParsedDomain::new("载.example.").unwrap();

        assert!(domain.name().is_ascii());
        assert!(domain.name().starts_with("xn--"));
        assert_eq!(domain.raw(), format!("{}.", domain.name()));
    }

    #[test]
    fn keeps_ascii_domains_lowercase_and_without_duplicate_root_dots() {
        let domain = ParsedDomain::new("WWW.Example.COM...").unwrap();

        assert_eq!(domain.name(), "www.example.com");
        assert_eq!(domain.raw(), "www.example.com.");
    }
}
