use std::sync::Arc;

use hickory_proto::rr::Name;
use landscape_common::dns::error::DnsServiceError;

pub(crate) use landscape_common::dns::domain::normalize_domain_text;

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
        let dns_name = parse_dns_name(normalized.as_ref(), fqdn)?;
        Ok(Self::canonicalize(dns_name))
    }

    pub fn from_wire_name(name: Name) -> Self {
        Self::canonicalize(name.to_lowercase())
    }

    // Hickory parses Unicode labels as IDNA and stores their ASCII/Punycode
    // form. Keep that canonical representation everywhere downstream so
    // byte-oriented matchers and suffix checks never see UTF-8 labels.
    fn canonicalize(dns_name: Name) -> Self {
        let name = dns_name.to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let labels: Vec<String> = name.split('.').map(String::from).collect();
        let raw = Arc::from(format!("{}.", name).as_str());
        Self { raw, name, labels, dns_name }
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

/// Parse domain text into a DNS name, keeping IDNA for Unicode labels while
/// also accepting DNS-only labels such as `xxx_xxx`.
///
/// `Name::from_str_relaxed` is whole-name: it falls back from IDNA to the
/// ASCII parser only when the entire name fails IDNA, so a mix of IDNA and
/// underscore labels fails both passes. Normalize that mixed case to ASCII
/// with the (non-strict) `idna` crate and parse the result as plain labels.
fn parse_dns_name(normalized: &str, original: &str) -> Result<Name, DnsServiceError> {
    if let Ok(name) = Name::from_str_relaxed(normalized) {
        return Ok(name);
    }

    let ascii = idna::domain_to_ascii(normalized)
        .map_err(|_| DnsServiceError::Invalid { domain: original.to_string() })?;
    Name::from_ascii(ascii).map_err(|_| DnsServiceError::Invalid { domain: original.to_string() })
}

#[cfg(test)]
mod tests {
    use hickory_proto::rr::Name;

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

    #[test]
    fn accepts_underscore_labels_after_the_first_character() {
        let domain = ParsedDomain::new("xxx_xxx.example.com.").unwrap();

        assert_eq!(domain.name(), "xxx_xxx.example.com");
        assert_eq!(domain.raw(), "xxx_xxx.example.com.");
        assert_eq!(domain.as_dns_name().to_ascii().trim_end_matches('.'), "xxx_xxx.example.com");
    }

    #[test]
    fn accepts_mixed_idna_and_underscore_labels() {
        let domain = ParsedDomain::new("xxx_xxx.测试.com.").unwrap();

        assert!(domain.name().is_ascii());
        assert!(domain.name().starts_with("xxx_xxx.xn--"));
        assert!(domain.name().ends_with(".com"));
        assert_eq!(domain.raw(), format!("{}.", domain.name()));
    }

    #[test]
    fn accepts_underscore_inside_unicode_labels() {
        let domain = ParsedDomain::new("测试_foo.com.").unwrap();

        assert!(domain.name().is_ascii());
        assert!(domain.name().starts_with("xn--"));
        assert!(domain.name().ends_with(".com"));
    }

    #[test]
    fn from_wire_name_matches_string_construction() {
        let wire = ParsedDomain::from_wire_name(Name::from_ascii("WWW.Example.COM.").unwrap());
        let text = ParsedDomain::new("www.example.com").unwrap();

        assert_eq!(wire.raw(), text.raw());
        assert_eq!(wire.name(), text.name());
        assert_eq!(
            wire.as_dns_name().to_ascii().trim_end_matches('.'),
            text.as_dns_name().to_ascii().trim_end_matches('.')
        );
    }
}
