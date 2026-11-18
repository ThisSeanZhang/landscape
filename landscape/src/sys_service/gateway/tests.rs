use super::*;
use crate::cert::account_service::CertAccountService;
use landscape_common::dns::redirect::DynamicDnsRedirectBatch;
use landscape_common::event::dns::DnsEvent;
use landscape_common::sys_service::gateway::{
    ClientIpHeaderPolicy, HttpUpstreamMatchRule, ProxyRequestHeader,
};
use landscape_database::provider::LandscapeDBServiceProvider;

async fn service() -> (GatewayService, CertService, tokio::sync::mpsc::Receiver<DnsEvent>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let db = LandscapeDBServiceProvider::mem_test_db().await;
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(32);
    let dns = DNSRedirectService::new(db.clone(), events_tx).await;
    let accounts = CertAccountService::new(db.clone()).await;
    let certs = CertService::new(db.clone(), accounts, Some(dns.clone())).await;
    let service = GatewayService::init_service(
        db.gateway_http_upstream_store(),
        GatewayRuntimeConfig::default(),
        &certs,
        dns,
    )
    .await
    .unwrap();
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

fn assert_dns_batches_eq(actual: &[DynamicDnsRedirectBatch], expected: &[DynamicDnsRedirectBatch]) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert_eq!(actual.source_id, expected.source_id);
        assert_eq!(actual.scope, expected.scope);
        assert_eq!(actual.records.len(), expected.records.len());
        for (actual, expected) in actual.records.iter().zip(&expected.records) {
            assert_eq!(actual.match_rule, expected.match_rule);
            assert_eq!(actual.answer_mode, expected.answer_mode);
            assert_eq!(actual.result_info, expected.result_info);
            assert_eq!(actual.ttl_secs, expected.ttl_secs);
            assert_eq!(actual.block_metadata_queries, expected.block_metadata_queries);
        }
    }
}

#[cfg(feature = "gateway")]
#[tokio::test]
async fn rule_mutations_update_storage_server_and_dns() {
    let (service, certs, _events_rx) = service().await;
    assert!(service.runtime_config().is_some());
    service.reload_rules().await.unwrap();
    let rule = service.save_rule(rule()).await.unwrap();
    assert_eq!(service.find_rule(rule.id).await.unwrap().unwrap().domains, rule.domains);
    assert_eq!(service.runtime.shared_routes().load().len(), 1);
    let batches = service.dns_redirect_service.list_dynamic_batches().await;
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].records.len(), 1);

    // Restart recreates the server from persistent rules without binding ports
    // when the gateway is disabled.
    service.restart(GatewayRuntimeConfig::default(), Duration::from_secs(1)).await.unwrap();
    assert_eq!(service.status(), ServiceStatus::Stop);
    assert_eq!(service.runtime.shared_routes().load().len(), 1);
    let before_routes = service.runtime.shared_routes().load_full();

    let mut conflict = rule.clone();
    conflict.id = uuid::Uuid::new_v4();
    assert!(matches!(service.save_rule(conflict).await, Err(GatewayError::HostConflict { .. })));
    let mut invalid = rule.clone();
    invalid.domains.clear();
    assert!(matches!(service.save_rule(invalid).await, Err(GatewayError::DomainsRequired { .. })));
    assert_eq!(service.stored_rule_count().await, 1);
    assert!(Arc::ptr_eq(&service.runtime.shared_routes().load_full(), &before_routes));
    assert_dns_batches_eq(&service.dns_redirect_service.list_dynamic_batches().await, &batches);

    service.delete_rule(rule.id).await.unwrap();
    assert!(service.find_rule(rule.id).await.unwrap().is_none());
    assert!(service.runtime.shared_routes().load().is_empty());
    assert!(service.dns_redirect_service.list_dynamic_batches().await.is_empty());
    service.shutdown_and_wait(Duration::from_secs(1)).await;
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}

#[cfg(feature = "gateway")]
#[tokio::test]
async fn legacy_sni_rules_support_load_reload_restart_and_unrelated_mutations() {
    let (initial, certs, _events_rx) = service().await;
    let sni = initial.store.upsert(legacy_sni_rule(None)).await.unwrap().new;
    let http = initial.store.upsert(rule()).await.unwrap().new;
    assert!(matches!(sni.upstream.client_ip_headers, ClientIpHeaderPolicy::Standard));

    let service = GatewayService::init_service(
        initial.store.clone(),
        GatewayRuntimeConfig::default(),
        &certs,
        initial.dns_redirect_service.clone(),
    )
    .await
    .unwrap();
    service.reload_rules().await.unwrap();
    service.restart(GatewayRuntimeConfig::default(), Duration::from_secs(1)).await.unwrap();
    assert_eq!(service.runtime.shared_routes().load().len(), 2);

    let read = service.find_rule(sni.id).await.unwrap().unwrap();
    assert!(matches!(read.upstream.client_ip_headers, ClientIpHeaderPolicy::None));
    let listed = service.list_rules().await.unwrap();
    assert!(matches!(
        listed.iter().find(|rule| rule.id == sni.id).unwrap().upstream.client_ip_headers,
        ClientIpHeaderPolicy::None
    ));
    assert!(matches!(
        listed.iter().find(|rule| rule.id == http.id).unwrap().upstream.client_ip_headers,
        ClientIpHeaderPolicy::Standard
    ));
    // Loading normalizes the API/runtime view without silently rewriting storage.
    assert!(matches!(
        Repository::find_by_id(&service.store, sni.id)
            .await
            .unwrap()
            .unwrap()
            .upstream
            .client_ip_headers,
        ClientIpHeaderPolicy::Standard
    ));

    let mut changed_http = http.clone();
    changed_http.name = "renamed-http".into();
    service.save_rule(changed_http).await.unwrap();
    service.delete_rule(http.id).await.unwrap();
    assert_eq!(service.runtime.shared_routes().load().len(), 1);

    // A caller can read a historical rule, change only its name and save it.
    let mut renamed = read;
    renamed.name = "renamed-sni".into();
    service.save_rule(renamed).await.unwrap();
    assert!(matches!(
        Repository::find_by_id(&service.store, sni.id)
            .await
            .unwrap()
            .unwrap()
            .upstream
            .client_ip_headers,
        ClientIpHeaderPolicy::None
    ));
    service.shutdown_and_wait(Duration::from_secs(1)).await;
    initial.shutdown_and_wait(Duration::from_secs(1)).await;
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}

#[cfg(feature = "gateway")]
#[tokio::test]
async fn new_sni_rules_keep_strict_header_validation() {
    let (service, certs, _events_rx) = service().await;
    for policy in [None, Some("standard")] {
        assert!(matches!(
            service.save_rule(legacy_sni_rule(policy)).await,
            Err(GatewayError::SniProxyHeaderUnsupported)
        ));
    }
    let mut with_header = legacy_sni_rule(Some("none"));
    with_header
        .upstream
        .request_headers
        .push(ProxyRequestHeader { name: "x-header".into(), value: "value".into() });
    assert!(matches!(
        service.save_rule(with_header).await,
        Err(GatewayError::SniProxyHeaderUnsupported)
    ));
    assert_eq!(service.stored_rule_count().await, 0);
    assert!(service.runtime.shared_routes().load().is_empty());
    assert!(service.dns_redirect_service.list_dynamic_batches().await.is_empty());
    service.save_rule(legacy_sni_rule(Some("none"))).await.unwrap();
    service.shutdown_and_wait(Duration::from_secs(1)).await;
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}

#[cfg(feature = "gateway")]
mod publication_failures {
    use super::*;
    use sea_orm::ConnectionTrait;

    #[tokio::test]
    async fn invalid_stored_candidate_preserves_live_rules_dns_and_existing_rows() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.save_rule(rule()).await.unwrap();
        let before_routes = service.runtime.shared_routes().load_full();
        let before_dns = service.dns_redirect_service.list_dynamic_batches().await;
        let before_config = service.runtime_config().unwrap();

        // Simulate a malformed rule imported outside the gateway service.
        let mut invalid = rule();
        invalid.domains = vec!["invalid.example.com".into()];
        invalid.upstream.request_headers = vec![ProxyRequestHeader {
            name: "invalid header".into(),
            value: "value".into(),
        }];
        let invalid = service.store.upsert(invalid).await.unwrap().new;
        assert!(matches!(
            service.reload_rules().await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        let mut replacement_config = before_config.clone();
        replacement_config.http_port += 1;
        assert!(matches!(
            service.restart(replacement_config, Duration::from_secs(1)).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        assert_eq!(service.runtime_config().unwrap().http_port, before_config.http_port);

        // Both mutations must prepare the whole candidate before changing storage.
        let mut changed = saved.clone();
        changed.domains = vec!["changed.example.com".into()];
        assert!(matches!(
            service.save_rule(changed).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        assert!(matches!(
            service.delete_rule(saved.id).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        let unchanged = service.find_rule(saved.id).await.unwrap().unwrap();
        assert_eq!(unchanged.domains, saved.domains);
        assert_eq!(unchanged.update_at, saved.update_at);
        assert_eq!(service.store.list().await.unwrap().len(), 2);

        service.sync_dynamic_dns_redirects().await;
        assert!(Arc::ptr_eq(&before_routes, &service.runtime.shared_routes().load_full()));
        assert_dns_batches_eq(
            &service.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );

        // Removing the malformed row produces a valid candidate and recovers normally.
        service.delete_rule(invalid.id).await.unwrap();
        assert_eq!(service.runtime.shared_routes().load().len(), 1);
        assert!(service.find_rule(invalid.id).await.unwrap().is_none());
        assert_dns_batches_eq(
            &service.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.shutdown_and_wait(Duration::from_secs(1)).await;
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn startup_rejects_invalid_persisted_rules() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.save_rule(rule()).await.unwrap();
        let before_routes = service.runtime.shared_routes().load_full();
        let before_dns = service.dns_redirect_service.list_dynamic_batches().await;
        let mut invalid = saved;
        invalid.upstream.request_headers = vec![ProxyRequestHeader {
            name: "x-invalid".into(),
            value: "line one\r\nline two".into(),
        }];
        service.store.upsert(invalid).await.unwrap();

        let result = GatewayService::init_service(
            service.store.clone(),
            GatewayRuntimeConfig::default(),
            &certs,
            service.dns_redirect_service.clone(),
        )
        .await;
        assert!(matches!(
            result,
            Err(GatewayServiceInitError::Rules(GatewayError::InvalidHeaderValue { .. }))
        ));
        assert!(Arc::ptr_eq(&before_routes, &service.runtime.shared_routes().load_full()));
        assert_dns_batches_eq(
            &service.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.shutdown_and_wait(Duration::from_secs(1)).await;
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn database_read_failures_preserve_published_rules_and_dns() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.save_rule(rule()).await.unwrap();
        let before_routes = service.runtime.shared_routes().load_full();
        let before_dns = service.dns_redirect_service.list_dynamic_batches().await;
        let before_config = service.runtime_config().unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
        Repository::db(&service.store).close_by_ref().await.unwrap();

        assert!(matches!(service.reload_rules().await, Err(GatewayError::Database(_))));
        assert!(matches!(service.save_rule(saved.clone()).await, Err(GatewayError::Database(_))));
        assert!(matches!(service.delete_rule(saved.id).await, Err(GatewayError::Database(_))));
        let mut replacement_config = before_config.clone();
        replacement_config.http_port += 1;
        assert!(matches!(
            service.restart(replacement_config, Duration::from_secs(1)).await,
            Err(GatewayError::Database(_))
        ));
        assert_eq!(service.runtime_config().unwrap().http_port, before_config.http_port);

        let result = GatewayService::init_service(
            service.store.clone(),
            GatewayRuntimeConfig::default(),
            &certs,
            service.dns_redirect_service.clone(),
        )
        .await;
        assert!(matches!(result, Err(GatewayServiceInitError::Rules(GatewayError::Database(_)))));
        service.sync_dynamic_dns_redirects().await;
        assert!(Arc::ptr_eq(&before_routes, &service.runtime.shared_routes().load_full()));
        assert_dns_batches_eq(
            &service.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn database_write_failures_do_not_publish_prepared_routes_or_dns() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.save_rule(rule()).await.unwrap();
        let before_routes = service.runtime.shared_routes().load_full();
        let before_dns = service.dns_redirect_service.list_dynamic_batches().await;
        let db = Repository::db(&service.store);
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            db.execute_unprepared(&format!(
                "CREATE TRIGGER reject_gateway_{operation} BEFORE {operation} ON \
                 gateway_http_upstream_rules BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"
            ))
            .await
            .unwrap();
        }

        let mut added = rule();
        added.domains = vec!["added.example.com".into()];
        assert!(matches!(service.save_rule(added.clone()).await, Err(GatewayError::Database(_))));
        let mut changed = saved.clone();
        changed.domains = vec!["changed.example.com".into()];
        assert!(matches!(service.save_rule(changed).await, Err(GatewayError::Database(_))));
        assert!(matches!(service.delete_rule(saved.id).await, Err(GatewayError::Database(_))));

        let unchanged = service.find_rule(saved.id).await.unwrap().unwrap();
        assert_eq!(unchanged.domains, saved.domains);
        assert_eq!(unchanged.update_at, saved.update_at);
        assert!(service.find_rule(added.id).await.unwrap().is_none());
        assert_eq!(service.store.list().await.unwrap().len(), 1);
        service.sync_dynamic_dns_redirects().await;
        assert!(Arc::ptr_eq(&before_routes, &service.runtime.shared_routes().load_full()));
        assert_dns_batches_eq(
            &service.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.shutdown_and_wait(Duration::from_secs(1)).await;
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }
}

#[cfg(not(feature = "gateway"))]
#[tokio::test]
async fn without_gateway_feature_service_remains_available_but_rejects_rules() {
    let (service, certs, _events_rx) = service().await;
    assert!(!service.is_supported());
    assert!(!service.has_https_listener());
    assert_eq!(service.status(), ServiceStatus::Stop);
    assert!(service.runtime_config().is_none());
    let cloned = service.clone();
    let stored = service.store.upsert(rule()).await.unwrap().new;
    service
        .dns_redirect_service
        .set_dynamic_batch(build_gateway_dynamic_dns_redirect_batch(std::slice::from_ref(&stored)))
        .await;
    let before_dns = service.dns_redirect_service.list_dynamic_batches().await;
    assert_eq!(before_dns.len(), 1);

    assert!(matches!(service.save_rule(rule()).await, Err(GatewayError::Unsupported)));
    assert!(matches!(service.list_rules().await, Err(GatewayError::Unsupported)));
    assert!(matches!(service.find_rule(stored.id).await, Err(GatewayError::Unsupported)));
    assert!(matches!(service.delete_rule(stored.id).await, Err(GatewayError::Unsupported)));
    assert!(matches!(service.reload_rules().await, Err(GatewayError::Unsupported)));
    let result = service
        .restart(
            GatewayRuntimeConfig { enable: true, http_port: 8080, https_port: 8443 },
            Duration::from_secs(1),
        )
        .await;
    assert!(matches!(result, Err(GatewayError::Unsupported)));
    assert!(service.runtime_config().is_none());
    assert!(cloned.runtime_config().is_none());
    assert_eq!(service.status(), ServiceStatus::Stop);
    let after_rules = service.store.list().await.unwrap();
    assert_eq!(after_rules.len(), 1);
    assert_eq!(after_rules[0].id, stored.id);
    assert_eq!(after_rules[0].domains, stored.domains);
    assert_eq!(service.stored_rule_count().await, 1);
    let after_dns = service.dns_redirect_service.list_dynamic_batches().await;
    assert_dns_batches_eq(&after_dns, &before_dns);

    // Startup synchronization explicitly removes stale gateway DNS records,
    // even when persistent rules exist in an unsupported build.
    service.sync_dynamic_dns_redirects().await;
    assert!(service.dns_redirect_service.list_dynamic_batches().await.is_empty());
    service.shutdown_and_wait(Duration::from_secs(1)).await;
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}
