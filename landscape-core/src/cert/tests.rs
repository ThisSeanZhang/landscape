use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair};

use super::pem::{build_certified_key_from_pem, extract_cert_dns_names_from_pem};
use super::resolver::{SharedSniResolver, TlsResolverEntry, build_resolver_snapshot_from_entries};

fn make_test_cert(configured_domains: &[&str], cert_domains: &[&str]) -> TlsResolverEntry {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let params = CertificateParams::new(
        cert_domains.iter().map(|domain| domain.to_string()).collect::<Vec<_>>(),
    )
    .expect("test certificate params should be valid");
    let signing_key = KeyPair::generate().expect("test key pair should generate");
    let certificate = params.self_signed(&signing_key).expect("test certificate should self-sign");
    let cert_pem = certificate.pem();
    let key_pem = signing_key.serialize_pem();
    let cert_names =
        extract_cert_dns_names_from_pem(&cert_pem).expect("generated cert names should parse");
    let certified_key = build_certified_key_from_pem(&cert_pem, None, &key_pem)
        .expect("generated cert should build certified key");

    TlsResolverEntry {
        cert_name: configured_domains.join(","),
        configured_domains: configured_domains.iter().map(|domain| domain.to_string()).collect(),
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
        vec![make_test_cert(&["*.example.com", "example.com"], &["*.example.com", "example.com"])],
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
    let exact = snapshot.exact.get("api.example.com").expect("exact entry should exist").clone();
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
