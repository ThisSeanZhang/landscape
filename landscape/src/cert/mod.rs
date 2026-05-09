use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

pub mod account_service;
pub mod dns_provider;
pub mod order_service;

use crate::cert::order_service::CertService;
use arc_swap::ArcSwap;
use arc_swap::ArcSwapOption;
use landscape_common::cert::order::{CertConfig, CertStatus, CertType};
use landscape_common::service::controller::ConfigController;
use landscape_common::utils::time::get_f64_timestamp;
use pem::parse_many;
use rcgen::generate_simple_self_signed;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use uuid::Uuid;

const AUTO_API_FALLBACK_CERT_NAME: &str = "Auto Generated API TLS Certificate";
const AUTO_API_FALLBACK_CERT_DOMAINS: [&str; 2] = ["landscape.local", "*.landscape.local"];

fn auto_api_fallback_domains() -> Vec<String> {
    AUTO_API_FALLBACK_CERT_DOMAINS.iter().map(|domain| domain.to_string()).collect()
}

fn has_expected_auto_api_fallback_domains(domains: &[String]) -> bool {
    let mut actual = domains.to_vec();
    let mut expected = auto_api_fallback_domains();
    actual.sort();
    expected.sort();
    actual == expected
}

fn is_usable_auto_api_fallback_cert(cert: &CertConfig) -> bool {
    cert.name == AUTO_API_FALLBACK_CERT_NAME
        && matches!(cert.status, CertStatus::Valid)
        && cert.certificate.as_ref().is_some()
        && cert.private_key.as_ref().is_some()
        && has_expected_auto_api_fallback_domains(&cert.domains)
}

#[derive(Clone)]
struct WildcardEntry {
    suffix: String,
    cert: Arc<CertifiedKey>,
}

#[derive(Clone, Default)]
struct ResolverSnapshot {
    exact: HashMap<String, Arc<CertifiedKey>>,
    wildcards: Vec<WildcardEntry>,
    fallback: Option<Arc<CertifiedKey>>,
}

impl ResolverSnapshot {
    fn resolve_name(&self, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
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

struct TlsResolverEntry {
    cert_name: String,
    configured_domains: Vec<String>,
    cert_names: Vec<String>,
    certified_key: CertifiedKey,
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

    fn swap(&self, snapshot: ResolverSnapshot) {
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

impl landscape_dns::server::DohAdvertiseProvider for SharedSniResolver {
    fn advertise_domains(&self) -> Vec<String> {
        self.advertised_domains()
    }
}

impl ResolvesServerCert for SharedSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(client_hello.server_name())
    }
}

/// Reload Gateway TLS SNI mappings from cert manager (`for_gateway=true`) into `shared_resolver`.
/// Unlike API TLS, no fallback self-signed cert is generated — if no valid gateway cert exists,
/// the resolver will simply have no entries.
pub async fn reload_gateway_tls_resolver(
    cert_service: &CertService,
    shared_resolver: &SharedSniResolver,
) -> Result<usize, String> {
    let mut candidates: Vec<CertConfig> = cert_service
        .list()
        .await
        .into_iter()
        .filter(|c| {
            c.for_gateway
                && matches!(c.status, CertStatus::Valid)
                && c.certificate.as_ref().is_some()
                && c.private_key.as_ref().is_some()
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.expires_at.partial_cmp(&a.expires_at).unwrap_or(std::cmp::Ordering::Equal).then_with(
            || b.update_at.partial_cmp(&a.update_at).unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    let mut tls_entries = Vec::new();
    for cert in candidates {
        let cert_pem = cert.certificate.as_deref().unwrap_or_default();
        let key_pem = cert.private_key.as_deref().unwrap_or_default();
        let chain_pem = cert.certificate_chain.as_deref();
        let cert_names = match extract_cert_dns_names_from_pem(cert_pem) {
            Ok(names) => names,
            Err(e) => {
                tracing::warn!("Skip invalid for_gateway cert '{}' ({})", cert.name, e);
                continue;
            }
        };
        match build_certified_key_from_pem(cert_pem, chain_pem, key_pem) {
            Ok(ck) => tls_entries.push(TlsResolverEntry {
                cert_name: cert.name.clone(),
                configured_domains: cert.domains.clone(),
                cert_names,
                certified_key: ck,
            }),
            Err(e) => tracing::warn!("Skip invalid for_gateway cert '{}' ({})", cert.name, e),
        }
    }

    let (snapshot, inserted_count) = build_resolver_snapshot_from_entries(tls_entries, None);
    shared_resolver.swap(snapshot);
    tracing::info!("Loaded {inserted_count} SNI domain mappings for Gateway TLS");
    Ok(inserted_count)
}

/// Reload API TLS SNI mappings from cert manager (`for_api=true`) into `shared_resolver`.
/// Ensures an auto-generated Manual `for_api` cert exists and uses it as fallback.
pub async fn reload_api_tls_resolver(
    cert_service: &CertService,
    shared_resolver: &SharedSniResolver,
) -> Result<usize, String> {
    let fallback_cert = ensure_auto_api_fallback_cert(cert_service).await?;

    let mut candidates: Vec<CertConfig> = cert_service
        .list()
        .await
        .into_iter()
        .filter(|c| {
            c.for_api
                && matches!(c.status, CertStatus::Valid)
                && c.certificate.as_ref().is_some()
                && c.private_key.as_ref().is_some()
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.expires_at.partial_cmp(&a.expires_at).unwrap_or(std::cmp::Ordering::Equal).then_with(
            || b.update_at.partial_cmp(&a.update_at).unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    if candidates.len() > 1 {
        tracing::info!("Multiple for_api certs found ({})", candidates.len());
    }

    let mut tls_entries = Vec::new();
    for cert in candidates {
        let cert_pem = cert.certificate.as_deref().unwrap_or_default();
        let key_pem = cert.private_key.as_deref().unwrap_or_default();
        let chain_pem = cert.certificate_chain.as_deref();
        let cert_names = match extract_cert_dns_names_from_pem(cert_pem) {
            Ok(names) => names,
            Err(e) => {
                tracing::warn!("Skip invalid for_api cert '{}' ({})", cert.name, e);
                continue;
            }
        };
        match build_certified_key_from_pem(cert_pem, chain_pem, key_pem) {
            Ok(ck) => tls_entries.push(TlsResolverEntry {
                cert_name: cert.name.clone(),
                configured_domains: cert.domains.clone(),
                cert_names,
                certified_key: ck,
            }),
            Err(e) => tracing::warn!("Skip invalid for_api cert '{}' ({})", cert.name, e),
        }
    }

    let fallback_ck = build_certified_key_from_pem(
        fallback_cert.certificate.as_deref().unwrap_or_default(),
        fallback_cert.certificate_chain.as_deref(),
        fallback_cert.private_key.as_deref().unwrap_or_default(),
    )
    .map_err(|e| format!("failed to build fallback API TLS cert: {e}"))?;
    let (snapshot, inserted_count) =
        build_resolver_snapshot_from_entries(tls_entries, Some(fallback_ck));
    shared_resolver.swap(snapshot);
    tracing::info!("Loaded {inserted_count} SNI domain mappings for API TLS");
    Ok(inserted_count)
}

pub fn build_tls_server_config_with_shared_resolver(
    shared_resolver: SharedSniResolver,
) -> ServerConfig {
    ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(shared_resolver))
}

pub fn validate_certified_key_from_pem(
    cert_pem: &str,
    chain_pem: Option<&str>,
    key_pem: &str,
) -> Result<(), String> {
    build_certified_key_from_pem(cert_pem, chain_pem, key_pem).map(|_| ())
}

fn parse_cert_validity_from_pem(cert_pem: &str) -> (Option<f64>, Option<f64>) {
    let Ok(pem_obj) = pem::parse(cert_pem) else {
        return (None, None);
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(pem_obj.contents()) else {
        return (None, None);
    };
    (
        Some(cert.validity().not_before.timestamp() as f64),
        Some(cert.validity().not_after.timestamp() as f64),
    )
}

pub(crate) fn extract_cert_dns_names_from_pem(cert_pem: &str) -> Result<Vec<String>, String> {
    let pem_obj =
        pem::parse(cert_pem).map_err(|e| format!("failed to parse certificate PEM: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem_obj.contents())
        .map_err(|e| format!("failed to parse X.509 certificate: {e}"))?;

    let mut names = Vec::new();
    let mut seen = HashSet::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    if let Some(normalized) = normalize_domain_name(dns) {
                        if seen.insert(normalized.clone()) {
                            names.push(normalized);
                        }
                    }
                }
            }
        }
    }

    if names.is_empty() {
        if let Some(cn) = cert.subject().iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                if let Some(normalized) = normalize_domain_name(cn_str) {
                    names.push(normalized);
                }
            }
        }
    }

    Ok(names)
}

fn build_resolver_snapshot_from_entries(
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

fn normalize_domain_name(domain: &str) -> Option<String> {
    let normalized = domain.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
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

fn build_certified_key_from_pem(
    cert_pem: &str,
    chain_pem: Option<&str>,
    key_pem: &str,
) -> Result<CertifiedKey, String> {
    let mut full_cert = cert_pem.to_string();
    if let Some(chain) = chain_pem {
        if !chain.trim().is_empty() {
            full_cert.push('\n');
            full_cert.push_str(chain);
        }
    }

    let cert_pems =
        parse_many(full_cert.as_bytes()).map_err(|e| format!("failed to parse cert PEM: {e}"))?;
    let certs: Vec<CertificateDer> = cert_pems
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.contents().to_vec()))
        .collect();
    if certs.is_empty() {
        return Err("no valid certificate found".to_string());
    }

    let key_pems =
        parse_many(key_pem.as_bytes()).map_err(|e| format!("failed to parse key PEM: {e}"))?;
    let private_key = key_pems
        .into_iter()
        .find_map(|p| match p.tag() {
            "PRIVATE KEY" => Some(PrivateKeyDer::Pkcs8(p.contents().to_vec().into())),
            "RSA PRIVATE KEY" => Some(PrivateKeyDer::Pkcs1(p.contents().to_vec().into())),
            "EC PRIVATE KEY" => Some(PrivateKeyDer::Sec1(p.contents().to_vec().into())),
            _ => None,
        })
        .ok_or_else(|| "no valid private key found".to_string())?;

    let provider = CryptoProvider::get_default()
        .ok_or_else(|| "rustls crypto provider is not installed".to_string())?;

    CertifiedKey::from_der(certs, private_key, provider)
        .map_err(|e| format!("invalid certified key: {e}"))
}

async fn ensure_auto_api_fallback_cert(cert_service: &CertService) -> Result<CertConfig, String> {
    let mut manual_for_api_certs: Vec<CertConfig> = cert_service
        .list()
        .await
        .into_iter()
        .filter(|c| c.for_api && matches!(c.cert_type, CertType::Manual))
        .collect();

    manual_for_api_certs.sort_by(|a, b| {
        b.expires_at.partial_cmp(&a.expires_at).unwrap_or(std::cmp::Ordering::Equal).then_with(
            || b.update_at.partial_cmp(&a.update_at).unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    if let Some(existing) = manual_for_api_certs.iter().find(|c| {
        c.name != AUTO_API_FALLBACK_CERT_NAME
            && matches!(c.status, CertStatus::Valid)
            && c.certificate.as_ref().is_some()
            && c.private_key.as_ref().is_some()
    }) {
        return Ok(existing.clone());
    }

    let existing_auto_fallback =
        manual_for_api_certs.into_iter().find(|c| c.name == AUTO_API_FALLBACK_CERT_NAME);

    if let Some(existing) =
        existing_auto_fallback.as_ref().filter(|cert| is_usable_auto_api_fallback_cert(cert))
    {
        return Ok(existing.clone());
    }

    tracing::warn!(
        "No usable manual for_api fallback cert found, generating a new self-signed one"
    );
    let subject_alt_names = auto_api_fallback_domains();
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names.clone())
            .map_err(|e| format!("failed to generate self-signed fallback cert: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let (issued_at, expires_at) = parse_cert_validity_from_pem(&cert_pem);

    let auto_cert = CertConfig {
        id: existing_auto_fallback.as_ref().map(|cert| cert.id).unwrap_or_else(Uuid::new_v4),
        name: AUTO_API_FALLBACK_CERT_NAME.to_string(),
        domains: subject_alt_names,
        status: CertStatus::Valid,
        private_key: Some(key_pem),
        certificate: Some(cert_pem),
        certificate_chain: None,
        expires_at,
        issued_at,
        status_message: None,
        cert_type: CertType::Manual,
        for_api: true,
        for_gateway: false,
        update_at: existing_auto_fallback
            .as_ref()
            .map(|cert| cert.update_at)
            .unwrap_or_else(get_f64_timestamp),
    };

    cert_service
        .checked_set(auto_cert)
        .await
        .map_err(|e| format!("failed to persist auto-generated fallback cert: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn make_test_cert(configured_domains: &[&str], cert_domains: &[&str]) -> TlsResolverEntry {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let params = CertificateParams::new(
            cert_domains.iter().map(|domain| domain.to_string()).collect::<Vec<_>>(),
        )
        .expect("test certificate params should be valid");
        let signing_key = KeyPair::generate().expect("test key pair should generate");
        let certificate =
            params.self_signed(&signing_key).expect("test certificate should self-sign");
        let cert_pem = certificate.pem();
        let key_pem = signing_key.serialize_pem();
        let cert_names =
            extract_cert_dns_names_from_pem(&cert_pem).expect("generated cert names should parse");
        let certified_key = build_certified_key_from_pem(&cert_pem, None, &key_pem)
            .expect("generated cert should build certified key");

        TlsResolverEntry {
            cert_name: configured_domains.join(","),
            configured_domains: configured_domains
                .iter()
                .map(|domain| domain.to_string())
                .collect(),
            cert_names,
            certified_key,
        }
    }

    #[test]
    fn exact_domain_is_resolved() {
        let (snapshot, inserted) = build_resolver_snapshot_from_entries(
            vec![make_test_cert(&["api.example.com"], &["api.example.com"])],
            None,
        );

        assert_eq!(inserted, 1);
        let expected = snapshot.exact.get("api.example.com").expect("exact mapping should exist");
        let resolved =
            snapshot.resolve_name(Some("api.example.com")).expect("exact host should resolve");
        assert!(Arc::ptr_eq(expected, &resolved));
    }

    #[test]
    fn wildcard_domain_matches_single_level_subdomain() {
        let (snapshot, inserted) = build_resolver_snapshot_from_entries(
            vec![make_test_cert(
                &["*.example.com", "example.com"],
                &["*.example.com", "example.com"],
            )],
            None,
        );

        assert_eq!(inserted, 2);
        let expected = snapshot
            .wildcards
            .iter()
            .find(|entry| entry.suffix == "example.com")
            .expect("wildcard entry should exist")
            .cert
            .clone();
        let resolved = snapshot
            .resolve_name(Some("api.example.com"))
            .expect("single-level subdomain should match wildcard");
        assert!(Arc::ptr_eq(&expected, &resolved));
    }

    #[test]
    fn wildcard_domain_does_not_match_bare_domain_or_nested_subdomain() {
        let (snapshot, _) = build_resolver_snapshot_from_entries(
            vec![make_test_cert(&["*.example.com"], &["*.example.com"])],
            None,
        );

        assert!(snapshot.resolve_name(Some("example.com")).is_none());
        assert!(snapshot.resolve_name(Some("foo.bar.example.com")).is_none());
    }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let (snapshot, inserted) = build_resolver_snapshot_from_entries(
            vec![
                make_test_cert(&["*.example.com"], &["*.example.com"]),
                make_test_cert(&["api.example.com"], &["api.example.com"]),
            ],
            None,
        );

        assert_eq!(inserted, 2);
        let exact =
            snapshot.exact.get("api.example.com").expect("exact entry should exist").clone();
        let resolved =
            snapshot.resolve_name(Some("api.example.com")).expect("exact host should resolve");
        assert!(Arc::ptr_eq(&exact, &resolved));
    }

    #[test]
    fn api_fallback_is_used_for_unmatched_host_and_missing_sni() {
        let fallback_entry = make_test_cert(
            &["landscape.local", "*.landscape.local"],
            &["landscape.local", "*.landscape.local"],
        );
        let fallback = fallback_entry.certified_key.clone();
        let (snapshot, inserted) = build_resolver_snapshot_from_entries(vec![], Some(fallback));

        assert_eq!(inserted, 0);
        let expected = snapshot.fallback.clone().expect("fallback should exist");
        let unmatched = snapshot
            .resolve_name(Some("unmatched.example.com"))
            .expect("fallback should resolve unmatched host");
        let missing_sni = snapshot.resolve_name(None).expect("fallback should resolve missing sni");

        assert!(Arc::ptr_eq(&expected, &unmatched));
        assert!(Arc::ptr_eq(&expected, &missing_sni));
    }

    #[test]
    fn legacy_localhost_auto_api_fallback_cert_is_not_reusable() {
        let legacy_cert = CertConfig {
            id: Uuid::new_v4(),
            name: AUTO_API_FALLBACK_CERT_NAME.to_string(),
            domains: vec!["localhost".to_string()],
            status: CertStatus::Valid,
            private_key: Some("key".to_string()),
            certificate: Some("cert".to_string()),
            certificate_chain: None,
            expires_at: None,
            issued_at: None,
            status_message: None,
            cert_type: CertType::Manual,
            for_api: true,
            for_gateway: false,
            update_at: 0.0,
        };

        assert!(!is_usable_auto_api_fallback_cert(&legacy_cert));
    }

    #[test]
    fn expected_auto_api_fallback_cert_is_reusable() {
        let auto_cert = CertConfig {
            id: Uuid::new_v4(),
            name: AUTO_API_FALLBACK_CERT_NAME.to_string(),
            domains: vec!["landscape.local".to_string(), "*.landscape.local".to_string()],
            status: CertStatus::Valid,
            private_key: Some("key".to_string()),
            certificate: Some("cert".to_string()),
            certificate_chain: None,
            expires_at: None,
            issued_at: None,
            status_message: None,
            cert_type: CertType::Manual,
            for_api: true,
            for_gateway: false,
            update_at: 0.0,
        };

        assert!(is_usable_auto_api_fallback_cert(&auto_cert));
    }

    #[test]
    fn unmatched_gateway_host_without_fallback_returns_none() {
        let (snapshot, _) = build_resolver_snapshot_from_entries(
            vec![make_test_cert(&["api.example.com"], &["api.example.com"])],
            None,
        );

        assert!(snapshot.resolve_name(Some("other.example.com")).is_none());
        assert!(snapshot.resolve_name(None).is_none());
    }

    #[test]
    fn wildcard_mapping_is_skipped_when_certificate_name_does_not_contain_pattern() {
        let (snapshot, inserted) = build_resolver_snapshot_from_entries(
            vec![make_test_cert(&["*.example.com"], &["api.example.com"])],
            None,
        );

        assert_eq!(inserted, 0);
        assert!(snapshot.wildcards.is_empty());
        assert!(snapshot.resolve_name(Some("api.example.com")).is_none());
    }

    #[test]
    fn advertised_domains_include_only_exact_domains() {
        let resolver = SharedSniResolver::new();
        let (snapshot, _) = build_resolver_snapshot_from_entries(
            vec![
                make_test_cert(&["*.example.com"], &["*.example.com"]),
                make_test_cert(&["api.example.com"], &["api.example.com"]),
            ],
            None,
        );

        resolver.swap(snapshot);

        assert_eq!(resolver.advertised_domains(), vec!["api.example.com".to_string()]);
    }
}
