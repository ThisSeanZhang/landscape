use super::*;
use crate::cert::account_service::CertAccountService;
use landscape_common::event::dns::DnsEvent;
use landscape_common::sys_service::gateway::{
    ClientIpHeaderPolicy, HttpUpstreamMatchRule, ProxyRequestHeader,
};
use landscape_database::provider::LandscapeDBServiceProvider;

use crate::{cert::order_service::CertService, sys_service::gateway::GatewayService};
use landscape_common::sys_config::GatewayRuntimeConfig;
use std::time::Duration;

#[cfg(not(feature = "gateway"))]
mod disabled;
#[cfg(feature = "gateway")]
mod enabled;

struct Fixture {
    rules: GatewayRuleConfigService,
    runtime: GatewayService,
}
async fn gateway_fixture(
    store: GatewayHttpUpstreamRepository,
    config: GatewayRuntimeConfig,
    certs: &CertService,
    dns: DNSRedirectService,
) -> Fixture {
    let rules = GatewayRuleConfigService::new(store, dns).await;
    let runtime = GatewayService::init_service(rules.clone(), config, certs).await;
    Fixture { rules, runtime }
}

async fn service() -> (Fixture, CertService, tokio::sync::mpsc::Receiver<DnsEvent>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(32);
    let dns = DNSRedirectService::new(db.clone(), events_tx).await;
    let accounts = CertAccountService::new(db.clone()).await;
    let certs = CertService::new(db.clone(), accounts, Some(dns.clone())).await;
    let service = gateway_fixture(
        db.gateway_http_upstream_store(),
        GatewayRuntimeConfig::default(),
        &certs,
        dns,
    )
    .await;
    (service, certs, events_rx)
}

fn rule() -> HttpUpstreamRuleConfig {
    serde_json::from_value(serde_json::json!({
        "id": uuid::Uuid::new_v4(),
        "name": "app",
        "enable": true,
        "domains": ["app.example.com"],
        "match_rule": { "t": "host" },
        "upstream": {
            "targets": [{ "address": "127.0.0.1", "port": 8080 }]
        }
    }))
    .unwrap()
}

#[tokio::test]
async fn concurrent_rule_edits_publish_a_complete_snapshot_without_a_runtime() {
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    let (events, _receiver) = tokio::sync::mpsc::channel(32);
    let dns = DNSRedirectService::new(db.clone(), events).await;
    let rules = GatewayRuleConfigService::new(db.gateway_http_upstream_store(), dns).await;
    let original = rules.routes.load_full();
    let first = rule();
    let mut second = rule();
    second.domains = vec!["other.example.com".into()];
    let (a, b) = tokio::join!(rules.save_rule(first), rules.save_rule(second));
    a.unwrap();
    b.unwrap();
    assert!(original.is_empty());
    let published = rules.routes.load_full();
    assert!(published.match_http_route(Some("app.example.com"), "/").is_some());
    assert!(published.match_http_route(Some("other.example.com"), "/").is_some());
    assert_eq!(rules.list_rules().await.unwrap().len(), 2);
}

fn legacy_sni_rule(policy: Option<&str>) -> HttpUpstreamRuleConfig {
    let mut config = serde_json::json!({
        "id": uuid::Uuid::new_v4(),
        "name": "legacy-sni",
        "enable": true,
        "match_rule": { "t": "sni_proxy", "domains": ["tls.example.com"] },
        "upstream": {
            "targets": [{ "address": "127.0.0.1", "port": 8443 }]
        }
    });
    if let Some(policy) = policy {
        config["upstream"]["client_ip_headers"] = policy.into();
    }
    serde_json::from_value(config).unwrap()
}

#[test]
fn import_preparation_normalizes_old_sni_and_preserves_http_defaults() {
    for policy in [None, Some("standard"), Some("none")] {
        let mut rules = vec![legacy_sni_rule(policy), rule()];
        prepare_gateway_rules_for_import(&mut rules).unwrap();
        assert!(matches!(rules[0].upstream.client_ip_headers, ClientIpHeaderPolicy::None));
        assert!(matches!(rules[1].upstream.client_ip_headers, ClientIpHeaderPolicy::Standard));

        // Persisted/imported data becomes canonical on its next serialization.
        assert_eq!(
            serde_json::to_value(&rules[0]).unwrap()["upstream"]["client_ip_headers"],
            "none"
        );
    }
}

#[test]
fn import_preparation_still_rejects_unsupported_sni_headers_and_bad_legacy_domains() {
    let mut sni = legacy_sni_rule(None);
    sni.upstream
        .request_headers
        .push(ProxyRequestHeader { name: "x-header".into(), value: "value".into() });
    assert!(matches!(
        prepare_gateway_rules_for_import(std::slice::from_mut(&mut sni)),
        Err(GatewayError::SniProxyHeaderUnsupported)
    ));

    let mut legacy = rule();
    legacy.match_rule = HttpUpstreamMatchRule::LegacyPathPrefix { prefix: "/legacy".into() };
    legacy.domains = vec![" . ".into()];
    assert!(matches!(
        prepare_gateway_rules_for_import(std::slice::from_mut(&mut legacy)),
        Err(GatewayError::DomainsRequired { .. })
    ));
    legacy.domains.clear();
    prepare_gateway_rules_for_import(std::slice::from_mut(&mut legacy)).unwrap();
}

#[tokio::test]
async fn new_sni_rules_keep_strict_header_validation() {
    let (service, certs, _events_rx) = service().await;
    for policy in [None, Some("standard")] {
        assert!(matches!(
            service.rules.save_rule(legacy_sni_rule(policy)).await,
            Err(GatewayError::SniProxyHeaderUnsupported)
        ));
    }
    let mut with_header = legacy_sni_rule(Some("none"));
    with_header
        .upstream
        .request_headers
        .push(ProxyRequestHeader { name: "x-header".into(), value: "value".into() });
    assert!(matches!(
        service.rules.save_rule(with_header).await,
        Err(GatewayError::SniProxyHeaderUnsupported)
    ));
    assert_eq!(service.rules.stored_rule_count().await, 0);
    assert!(service.rules.routes.load().is_empty());
    assert!(service.rules.dns_redirect_service.list_dynamic_batches().await.is_empty());
    service.rules.save_rule(legacy_sni_rule(Some("none"))).await.unwrap();
    service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}
