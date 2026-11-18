use super::*;
use landscape_common::dns::redirect::DynamicDnsRedirectBatch;
use landscape_common::service::ServiceStatus;
use landscape_database::repository::Repository;

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

#[tokio::test]
async fn rule_mutations_update_storage_server_and_dns() {
    let (service, certs, _events_rx) = service().await;
    assert!(service.runtime.runtime_config().is_some());
    service.rules.reload_rules().await.unwrap();
    let rule = service.rules.save_rule(rule()).await.unwrap();
    assert_eq!(service.rules.find_rule(rule.id).await.unwrap().unwrap().domains, rule.domains);
    assert_eq!(service.rules.routes.load().len(), 1);
    let batches = service.rules.dns_redirect_service.list_dynamic_batches().await;
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].records.len(), 1);

    // Disabling retains the published routes without binding any ports.
    service.runtime.restart(GatewayRuntimeConfig::default(), Duration::from_secs(1)).await.unwrap();
    assert_eq!(service.runtime.status(), ServiceStatus::Stop);
    assert_eq!(service.rules.routes.load().len(), 1);
    let before_routes = service.rules.routes.load_full();

    let mut conflict = rule.clone();
    conflict.id = uuid::Uuid::new_v4();
    assert!(matches!(
        service.rules.save_rule(conflict).await,
        Err(GatewayError::HostConflict { .. })
    ));
    let mut invalid = rule.clone();
    invalid.domains.clear();
    assert!(matches!(
        service.rules.save_rule(invalid).await,
        Err(GatewayError::DomainsRequired { .. })
    ));
    assert_eq!(service.rules.stored_rule_count().await, 1);
    assert!(Arc::ptr_eq(&service.rules.routes.load_full(), &before_routes));
    assert_dns_batches_eq(
        &service.rules.dns_redirect_service.list_dynamic_batches().await,
        &batches,
    );

    service.rules.delete_rule(rule.id).await.unwrap();
    assert!(service.rules.find_rule(rule.id).await.unwrap().is_none());
    assert!(service.rules.routes.load().is_empty());
    assert!(service.rules.dns_redirect_service.list_dynamic_batches().await.is_empty());
    service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn legacy_sni_rules_support_load_reload_restart_and_unrelated_mutations() {
    let (initial, certs, _events_rx) = service().await;
    let sni = initial.rules.store.upsert(legacy_sni_rule(None)).await.unwrap().new;
    let http = initial.rules.store.upsert(rule()).await.unwrap().new;
    assert!(matches!(sni.upstream.client_ip_headers, ClientIpHeaderPolicy::Standard));

    let service = gateway_fixture(
        initial.rules.store.clone(),
        GatewayRuntimeConfig::default(),
        &certs,
        initial.rules.dns_redirect_service.clone(),
    )
    .await;
    service.rules.reload_rules().await.unwrap();
    service.runtime.restart(GatewayRuntimeConfig::default(), Duration::from_secs(1)).await.unwrap();
    assert_eq!(service.rules.routes.load().len(), 2);

    let read = service.rules.find_rule(sni.id).await.unwrap().unwrap();
    assert!(matches!(read.upstream.client_ip_headers, ClientIpHeaderPolicy::None));
    let listed = service.rules.list_rules().await.unwrap();
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
        Repository::find_by_id(&service.rules.store, sni.id)
            .await
            .unwrap()
            .unwrap()
            .upstream
            .client_ip_headers,
        ClientIpHeaderPolicy::Standard
    ));

    let mut changed_http = http.clone();
    changed_http.name = "renamed-http".into();
    service.rules.save_rule(changed_http).await.unwrap();
    service.rules.delete_rule(http.id).await.unwrap();
    assert_eq!(service.rules.routes.load().len(), 1);

    // A caller can read a historical rule, change only its name and save it.
    let mut renamed = read;
    renamed.name = "renamed-sni".into();
    service.rules.save_rule(renamed).await.unwrap();
    assert!(matches!(
        Repository::find_by_id(&service.rules.store, sni.id)
            .await
            .unwrap()
            .unwrap()
            .upstream
            .client_ip_headers,
        ClientIpHeaderPolicy::None
    ));
    service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
    initial.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}

mod publication_failures {
    use super::*;
    use sea_orm::ConnectionTrait;

    #[tokio::test]
    async fn invalid_stored_candidate_preserves_live_rules_dns_and_existing_rows() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.rules.save_rule(rule()).await.unwrap();
        let before_routes = service.rules.routes.load_full();
        let before_dns = service.rules.dns_redirect_service.list_dynamic_batches().await;
        let before_config = service.runtime.runtime_config().unwrap();

        // Simulate a malformed rule imported outside the gateway service.
        let mut invalid = rule();
        invalid.domains = vec!["invalid.example.com".into()];
        invalid.upstream.request_headers = vec![ProxyRequestHeader {
            name: "invalid header".into(),
            value: "value".into(),
        }];
        let invalid = service.rules.store.upsert(invalid).await.unwrap().new;
        assert!(matches!(
            service.rules.reload_rules().await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        let mut replacement_config = before_config.clone();
        replacement_config.enable = true;
        replacement_config.http_port = 0;
        replacement_config.https_port = 0;
        service.runtime.restart(replacement_config, Duration::from_secs(5)).await.unwrap();

        // Both mutations must prepare the whole candidate before changing storage.
        let mut changed = saved.clone();
        changed.domains = vec!["changed.example.com".into()];
        assert!(matches!(
            service.rules.save_rule(changed).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        assert!(matches!(
            service.rules.delete_rule(saved.id).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        let unchanged = service.rules.find_rule(saved.id).await.unwrap().unwrap();
        assert_eq!(unchanged.domains, saved.domains);
        assert_eq!(unchanged.update_at, saved.update_at);
        assert_eq!(service.rules.store.list().await.unwrap().len(), 2);

        service.rules.sync_dynamic_dns_redirects().await;
        assert!(Arc::ptr_eq(&before_routes, &service.rules.routes.load_full()));
        assert_dns_batches_eq(
            &service.rules.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );

        // Removing the malformed row produces a valid candidate and recovers normally.
        service.rules.delete_rule(invalid.id).await.unwrap();
        assert_eq!(service.rules.routes.load().len(), 1);
        assert!(service.rules.find_rule(invalid.id).await.unwrap().is_none());
        assert_dns_batches_eq(
            &service.rules.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn startup_isolates_invalid_persisted_rules() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.rules.save_rule(rule()).await.unwrap();
        let before_routes = service.rules.routes.load_full();
        let before_dns = service.rules.dns_redirect_service.list_dynamic_batches().await;
        let mut invalid = saved;
        invalid.upstream.request_headers = vec![ProxyRequestHeader {
            name: "x-invalid".into(),
            value: "line one\r\nline two".into(),
        }];
        service.rules.store.upsert(invalid).await.unwrap();

        let result = gateway_fixture(
            service.rules.store.clone(),
            GatewayRuntimeConfig::default(),
            &certs,
            service.rules.dns_redirect_service.clone(),
        )
        .await;
        assert_eq!(result.runtime.status(), ServiceStatus::Failed);
        assert!(result.runtime.last_error().unwrap().contains("x-invalid"));
        assert!(!result.runtime.has_https_listener());
        assert!(result.rules.published_dns.lock().await.records.is_empty());
        assert!(Arc::ptr_eq(&before_routes, &service.rules.routes.load_full()));
        assert_dns_batches_eq(
            &service.rules.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn database_read_failures_preserve_published_rules_and_dns() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.rules.save_rule(rule()).await.unwrap();
        let before_routes = service.rules.routes.load_full();
        let before_dns = service.rules.dns_redirect_service.list_dynamic_batches().await;
        let before_config = service.runtime.runtime_config().unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
        Repository::db(&service.rules.store).close_by_ref().await.unwrap();

        assert!(matches!(service.rules.reload_rules().await, Err(GatewayError::Database(_))));
        assert!(matches!(
            service.rules.save_rule(saved.clone()).await,
            Err(GatewayError::Database(_))
        ));
        assert!(matches!(
            service.rules.delete_rule(saved.id).await,
            Err(GatewayError::Database(_))
        ));
        let mut replacement_config = before_config.clone();
        replacement_config.enable = true;
        replacement_config.http_port += 1;
        assert!(matches!(
            service.runtime.restart(replacement_config, Duration::from_secs(1)).await,
            Err(GatewayError::Certificate(_))
        ));
        assert_eq!(service.runtime.runtime_config().unwrap().http_port, before_config.http_port);

        let result = gateway_fixture(
            service.rules.store.clone(),
            GatewayRuntimeConfig::default(),
            &certs,
            service.rules.dns_redirect_service.clone(),
        )
        .await;
        assert_eq!(result.runtime.status(), ServiceStatus::Failed);
        assert!(result.runtime.last_error().is_some());
        assert!(result.rules.published_dns.lock().await.records.is_empty());
        service.rules.sync_dynamic_dns_redirects().await;
        assert!(Arc::ptr_eq(&before_routes, &service.rules.routes.load_full()));
        assert_dns_batches_eq(
            &service.rules.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
    }

    #[tokio::test]
    async fn database_write_failures_do_not_publish_prepared_routes_or_dns() {
        let (service, certs, _events_rx) = service().await;
        let saved = service.rules.save_rule(rule()).await.unwrap();
        let before_routes = service.rules.routes.load_full();
        let before_dns = service.rules.dns_redirect_service.list_dynamic_batches().await;
        let db = Repository::db(&service.rules.store);
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
        assert!(matches!(
            service.rules.save_rule(added.clone()).await,
            Err(GatewayError::Database(_))
        ));
        let mut changed = saved.clone();
        changed.domains = vec!["changed.example.com".into()];
        assert!(matches!(service.rules.save_rule(changed).await, Err(GatewayError::Database(_))));
        assert!(matches!(
            service.rules.delete_rule(saved.id).await,
            Err(GatewayError::Database(_))
        ));

        let unchanged = service.rules.find_rule(saved.id).await.unwrap().unwrap();
        assert_eq!(unchanged.domains, saved.domains);
        assert_eq!(unchanged.update_at, saved.update_at);
        assert!(service.rules.find_rule(added.id).await.unwrap().is_none());
        assert_eq!(service.rules.store.list().await.unwrap().len(), 1);
        service.rules.sync_dynamic_dns_redirects().await;
        assert!(Arc::ptr_eq(&before_routes, &service.rules.routes.load_full()));
        assert_dns_batches_eq(
            &service.rules.dns_redirect_service.list_dynamic_batches().await,
            &before_dns,
        );
        service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn live_routes_survive_hot_updates_and_concurrent_restart() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        let (service, certs, _events) = service().await;
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut candidate = rule();
        candidate.upstream.targets[0].port = upstream.local_addr().unwrap().port();
        let reservation = TcpListener::bind("[::1]:0").await.unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        let config = GatewayRuntimeConfig { enable: true, http_port: port, https_port: 0 };
        let timeout = Duration::from_secs(5);
        let client = reqwest::Client::builder().no_proxy().timeout(timeout).build().unwrap();
        let request = || async {
            tokio::time::timeout(timeout, async {
                loop {
                    match client
                        .get(format!("http://[::1]:{port}/"))
                        .header("Host", "app.example.com")
                        .send()
                        .await
                    {
                        Ok(response) => break response.status().as_u16(),
                        Err(error) if error.is_connect() => {
                            tokio::time::sleep(Duration::from_millis(5)).await
                        }
                        Err(error) => panic!("gateway request failed: {error}"),
                    }
                }
            })
            .await
            .unwrap()
        };
        service.runtime.restart(config.clone(), timeout).await.unwrap();
        assert_eq!(request().await, 404);
        let saved = service.rules.save_rule(candidate).await.unwrap();
        let respond = async {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buf = [0; 4096];
            assert!(stream.read(&mut buf).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        };
        let (_, status) = tokio::time::timeout(timeout, async { tokio::join!(respond, request()) })
            .await
            .unwrap();
        assert_eq!(status, 204);

        let (deleted, restarted) = tokio::join!(
            service.rules.delete_rule(saved.id),
            service.runtime.restart(config, timeout)
        );
        deleted.unwrap();
        restarted.unwrap();
        assert_eq!(request().await, 404);
        assert!(service.rules.routes.load().is_empty());
        assert!(
            service
                .rules
                .dns_redirect_service
                .list_dynamic_batches()
                .await
                .iter()
                .all(|batch| batch.records.is_empty())
        );
        service.runtime.shutdown_and_wait(timeout).await.unwrap();
        certs.shutdown_and_wait(timeout).await;
    }

    #[tokio::test]
    async fn running_gateway_updates_and_disables_without_unneeded_storage_reads() {
        for table in ["gateway_http_upstream_rules", "certs"] {
            let (service, certs, _events_rx) = service().await;
            service.rules.save_rule(rule()).await.unwrap();
            let reserved = std::net::TcpListener::bind("[::]:0").unwrap();
            let https_port = reserved.local_addr().unwrap().port();
            drop(reserved);
            let config = GatewayRuntimeConfig { enable: true, http_port: 0, https_port };
            service.runtime.restart(config.clone(), Duration::from_secs(5)).await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while service.runtime.status() != ServiceStatus::Running
                    || !service.runtime.has_https_listener()
                {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .unwrap();

            // Stop certificate background jobs before making their shared database
            // unavailable, so this test exercises only gateway-triggered reads.
            certs.shutdown_and_wait(Duration::from_secs(1)).await;
            let db = Repository::db(&service.rules.store);
            db.execute_unprepared(&format!(
                "ALTER TABLE {table} RENAME TO unavailable_gateway_table"
            ))
            .await
            .unwrap();
            if table == "certs" {
                assert!(certs.reload_gateway_tls_mapping().await.is_err());
                let before_routes = service.rules.routes.load_full();
                let mut added = rule();
                added.domains = vec!["added.example.com".into()];
                let saved = service.rules.save_rule(added).await.unwrap();
                assert_eq!(
                    service.rules.find_rule(saved.id).await.unwrap().unwrap().domains,
                    saved.domains
                );
                assert!(!Arc::ptr_eq(&before_routes, &service.rules.routes.load_full()));
                assert_eq!(service.rules.routes.load().len(), 2);
                assert_eq!(
                    service.rules.dns_redirect_service.list_dynamic_batches().await[0]
                        .records
                        .len(),
                    2
                );
                assert_eq!(service.runtime.status(), ServiceStatus::Running);
                assert!(service.runtime.has_https_listener());

                // Disable must also avoid compiling rules changed outside the service.
                let mut invalid = rule();
                invalid.domains = vec!["invalid.example.com".into()];
                invalid.upstream.request_headers = vec![ProxyRequestHeader {
                    name: "invalid header".into(),
                    value: "value".into(),
                }];
                service.rules.store.upsert(invalid).await.unwrap();
            } else {
                assert!(matches!(service.rules.list_rules().await, Err(GatewayError::Database(_))));
            }

            let before_routes = service.rules.routes.load_full();
            let before_dns = service.rules.dns_redirect_service.list_dynamic_batches().await;
            let disabled = GatewayRuntimeConfig { enable: false, ..config };
            service.runtime.restart(disabled, Duration::from_secs(5)).await.unwrap();
            assert_eq!(service.runtime.status(), ServiceStatus::Stop);
            assert!(!service.runtime.has_https_listener());
            assert!(!service.runtime.runtime_config().unwrap().enable);
            assert_eq!(service.runtime.runtime_config().unwrap().https_port, https_port);
            assert!(service.runtime.last_error().is_none());
            assert!(Arc::ptr_eq(&before_routes, &service.rules.routes.load_full()));
            assert_dns_batches_eq(
                &service.rules.dns_redirect_service.list_dynamic_batches().await,
                &before_dns,
            );
            let rebound =
                std::net::TcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, https_port))
                    .expect("disabling the gateway must release its HTTPS listener");
            service.rules.sync_dynamic_dns_redirects().await;
            assert_dns_batches_eq(
                &service.rules.dns_redirect_service.list_dynamic_batches().await,
                &before_dns,
            );
            service.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
            drop(rebound);
            db.execute_unprepared(&format!(
                "ALTER TABLE unavailable_gateway_table RENAME TO {table}"
            ))
            .await
            .unwrap();
        }
    }
}

mod initialization_failures {
    use super::*;
    use sea_orm::ConnectionTrait;

    fn invalid_rule(name: &str) -> HttpUpstreamRuleConfig {
        let mut rule = rule();
        rule.name = name.into();
        rule.domains = vec![format!("{name}.example.com")];
        rule.upstream.request_headers = vec![ProxyRequestHeader {
            name: format!("invalid {name}"),
            value: "value".into(),
        }];
        rule
    }

    async fn assert_uninitialized(service: &Fixture) {
        assert_eq!(service.runtime.status(), ServiceStatus::Failed);
        assert!(service.runtime.last_error().is_some());
        assert!(!service.runtime.has_https_listener());
    }

    #[tokio::test]
    async fn repairs_publish_when_the_entire_rule_set_is_valid() {
        let (initial, certs, _events_rx) = service().await;
        let mut first = initial.rules.store.upsert(invalid_rule("first")).await.unwrap().new;
        let second = initial.rules.store.upsert(invalid_rule("second")).await.unwrap().new;
        let third = initial.rules.store.upsert(invalid_rule("third")).await.unwrap().new;
        for enable in [true, false] {
            let failed = gateway_fixture(
                initial.rules.store.clone(),
                GatewayRuntimeConfig { enable, ..GatewayRuntimeConfig::default() },
                &certs,
                initial.rules.dns_redirect_service.clone(),
            )
            .await;
            assert_uninitialized(&failed).await;
            assert_eq!(failed.runtime.runtime_config().unwrap().enable, enable);
            assert_eq!(failed.rules.list_rules().await.unwrap().len(), 3);
            assert!(failed.rules.find_rule(first.id).await.unwrap().is_some());
            failed.rules.sync_dynamic_dns_redirects().await;
            assert!(failed.rules.dns_redirect_service.list_dynamic_batches().await.is_empty());
        }

        let failed = gateway_fixture(
            initial.rules.store.clone(),
            GatewayRuntimeConfig::default(),
            &certs,
            initial.rules.dns_redirect_service.clone(),
        )
        .await;
        let rejected = invalid_rule("new");
        assert!(matches!(
            failed.rules.save_rule(rejected.clone()).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        assert!(failed.rules.find_rule(rejected.id).await.unwrap().is_none());
        assert!(matches!(
            failed.rules.save_rule(legacy_sni_rule(None)).await,
            Err(GatewayError::SniProxyHeaderUnsupported)
        ));

        first.upstream.request_headers.clear();
        failed.rules.save_rule(first.clone()).await.unwrap();
        assert_uninitialized(&failed).await;
        assert!(failed.runtime.last_error().unwrap().contains("invalid"));
        // Deleting another row succeeds even while a third invalid row remains.
        failed.rules.delete_rule(second.id).await.unwrap();
        assert_uninitialized(&failed).await;
        assert!(matches!(
            failed.rules.reload_rules().await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        assert!(failed.runtime.last_error().unwrap().contains("invalid third"));

        failed.rules.delete_rule(third.id).await.unwrap();
        assert_uninitialized(&failed).await;
        assert!(failed.runtime.last_error().unwrap().contains("restart"));
        failed.rules.reload_rules().await.unwrap();
        assert_uninitialized(&failed).await;
        failed.rules.sync_dynamic_dns_redirects().await;
        assert_eq!(
            failed.rules.dns_redirect_service.list_dynamic_batches().await[0].records.len(),
            1
        );

        failed
            .runtime
            .restart(GatewayRuntimeConfig::default(), Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(failed.runtime.status(), ServiceStatus::Stop);
        assert!(failed.runtime.last_error().is_none());
        assert_eq!(failed.rules.routes.load().len(), 1);
        assert_eq!(
            failed.rules.dns_redirect_service.list_dynamic_batches().await[0].records.len(),
            1
        );
        failed.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        initial.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn rule_and_certificate_query_failures_are_local_and_retryable() {
        for table in ["gateway_http_upstream_rules", "certs"] {
            let (initial, certs, _events_rx) = service().await;
            certs.shutdown_and_wait(Duration::from_secs(1)).await;
            let before_routes = initial.rules.routes.load_full();
            let before_config = initial.runtime.runtime_config().unwrap();
            let db = Repository::db(&initial.rules.store);
            db.execute_unprepared(&format!(
                "ALTER TABLE {table} RENAME TO unavailable_gateway_table"
            ))
            .await
            .unwrap();

            for enable in [true, false] {
                let failed = gateway_fixture(
                    initial.rules.store.clone(),
                    GatewayRuntimeConfig { enable, ..GatewayRuntimeConfig::default() },
                    &certs,
                    initial.rules.dns_redirect_service.clone(),
                )
                .await;
                if table == "certs" && !enable {
                    assert_eq!(failed.runtime.status(), ServiceStatus::Stop);
                    assert!(failed.runtime.last_error().is_none());
                    continue;
                }
                assert_uninitialized(&failed).await;
                assert_eq!(failed.runtime.runtime_config().unwrap().enable, enable);
                assert!(failed.rules.dns_redirect_service.list_dynamic_batches().await.is_empty());
                let restart = failed
                    .runtime
                    .restart(
                        GatewayRuntimeConfig { enable, ..Default::default() },
                        Duration::from_secs(1),
                    )
                    .await;
                if !enable {
                    restart.unwrap();
                    assert_eq!(failed.runtime.status(), ServiceStatus::Stop);
                    assert!(failed.runtime.last_error().is_some());
                    continue;
                }
                if table == "certs" {
                    assert!(matches!(restart, Err(GatewayError::Certificate(_))));
                    assert!(failed.rules.list_rules().await.unwrap().is_empty());
                } else {
                    assert!(matches!(restart, Err(GatewayError::Database(_))));
                    assert!(matches!(
                        failed.rules.list_rules().await,
                        Err(GatewayError::Database(_))
                    ));
                    assert_eq!(
                        failed.runtime.last_error().as_deref(),
                        Some("Database operation failed, please try again later")
                    );
                }
                assert_uninitialized(&failed).await;
            }

            // Preparation failures on a previously Ready instance retain its
            // published configuration and routes, without enabling repair mode.
            let mut changed_config = before_config.clone();
            changed_config.enable = true;
            changed_config.http_port = 0;
            changed_config.https_port = 0;
            let restart = initial.runtime.restart(changed_config, Duration::from_secs(1)).await;
            if table == "certs" {
                assert!(matches!(restart, Err(GatewayError::Certificate(_))));
                assert_eq!(
                    initial.runtime.runtime_config().unwrap().http_port,
                    before_config.http_port
                );
            } else {
                restart.unwrap();
                assert_eq!(initial.runtime.runtime_config().unwrap().http_port, 0);
            }
            assert!(initial.runtime.last_error().is_none());
            assert!(Arc::ptr_eq(&before_routes, &initial.rules.routes.load_full()));

            let failed = gateway_fixture(
                initial.rules.store.clone(),
                GatewayRuntimeConfig::default(),
                &certs,
                initial.rules.dns_redirect_service.clone(),
            )
            .await;
            db.execute_unprepared(&format!(
                "ALTER TABLE unavailable_gateway_table RENAME TO {table}"
            ))
            .await
            .unwrap();
            // An explicit rule reload recovers the snapshot after storage is restored.
            failed.rules.reload_rules().await.unwrap();
            failed
                .runtime
                .restart(GatewayRuntimeConfig::default(), Duration::from_secs(1))
                .await
                .unwrap();
            assert_eq!(failed.runtime.status(), ServiceStatus::Stop);
            assert!(failed.runtime.last_error().is_none());
            failed.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
            initial.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn failed_existing_backend_does_not_enable_partial_repair() {
        let (initial, certs, _events_rx) = service().await;
        let occupied = std::net::TcpListener::bind("[::]:0").unwrap();
        let gateway = gateway_fixture(
            initial.rules.store.clone(),
            GatewayRuntimeConfig {
                enable: true,
                http_port: 0,
                https_port: occupied.local_addr().unwrap().port(),
            },
            &certs,
            initial.rules.dns_redirect_service.clone(),
        )
        .await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while gateway.runtime.status() != ServiceStatus::Failed {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert!(
            gateway
                .runtime
                .last_error()
                .unwrap()
                .contains(&occupied.local_addr().unwrap().to_string())
        );
        let first = gateway.rules.store.upsert(invalid_rule("first")).await.unwrap().new;
        gateway.rules.store.upsert(invalid_rule("second")).await.unwrap();
        let mut repaired = first.clone();
        repaired.upstream.request_headers.clear();
        assert!(matches!(
            gateway.rules.save_rule(repaired).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        assert!(matches!(
            gateway.rules.delete_rule(first.id).await,
            Err(GatewayError::InvalidHeaderName { .. })
        ));
        assert_eq!(gateway.rules.store.list().await.unwrap().len(), 2);
        gateway.runtime.shutdown_and_wait(Duration::from_secs(5)).await.unwrap();
        initial.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn malformed_json_is_reported_without_panicking_and_can_be_deleted_by_id() {
        use landscape_database::gateway::entity::GatewayHttpUpstreamActiveModel;
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let (initial, certs, _events_rx) = service().await;
        let bad_match = initial.rules.store.upsert(rule()).await.unwrap().new;
        let mut upstream_rule = rule();
        upstream_rule.domains = vec!["upstream.example.com".into()];
        let bad_upstream = initial.rules.store.upsert(upstream_rule).await.unwrap().new;
        let mut good_rule = rule();
        good_rule.domains = vec!["good.example.com".into()];
        let good = initial.rules.store.upsert(good_rule).await.unwrap().new;
        let db = Repository::db(&initial.rules.store);
        let mut model: GatewayHttpUpstreamActiveModel = bad_match.clone().into();
        model.match_rule = Set(serde_json::json!({ "t": "private-invalid-variant" }));
        model.update(db).await.unwrap();
        let mut model: GatewayHttpUpstreamActiveModel = bad_upstream.clone().into();
        model.upstream = Set(serde_json::json!({ "targets": "private-upstream-value" }));
        model.update(db).await.unwrap();

        // All normal service reads are checked; even a Ready instance rejects
        // malformed stored JSON before calling an infallible generic writer.
        let before_routes = initial.rules.routes.load_full();
        assert!(matches!(
            initial.rules.save_rule(good.clone()).await,
            Err(GatewayError::InvalidStoredRule { .. })
        ));
        assert!(matches!(
            initial.rules.delete_rule(bad_match.id).await,
            Err(GatewayError::InvalidStoredRule { .. })
        ));
        assert!(Arc::ptr_eq(&before_routes, &initial.rules.routes.load_full()));

        for enable in [true, false] {
            let failed = gateway_fixture(
                initial.rules.store.clone(),
                GatewayRuntimeConfig { enable, ..GatewayRuntimeConfig::default() },
                &certs,
                initial.rules.dns_redirect_service.clone(),
            )
            .await;
            assert_uninitialized(&failed).await;
            assert_eq!(failed.rules.stored_rule_count().await, 3);
            assert!(!failed.runtime.last_error().unwrap().contains("private-"));
            assert!(matches!(
                failed.rules.list_rules().await,
                Err(GatewayError::InvalidStoredRule { .. })
            ));
            assert!(matches!(
                failed.rules.find_rule(bad_match.id).await,
                Err(GatewayError::InvalidStoredRule { id, reason })
                    if id == bad_match.id && reason == "invalid 'match_rule' configuration"
            ));
            assert!(matches!(
                failed.rules.find_rule(bad_upstream.id).await,
                Err(GatewayError::InvalidStoredRule { id, reason })
                    if id == bad_upstream.id && reason == "invalid 'upstream' configuration"
            ));
            assert_eq!(
                failed.rules.find_rule(good.id).await.unwrap().unwrap().domains,
                good.domains
            );
            assert!(failed.rules.dns_redirect_service.list_dynamic_batches().await.is_empty());
        }

        let failed = gateway_fixture(
            initial.rules.store.clone(),
            GatewayRuntimeConfig::default(),
            &certs,
            initial.rules.dns_redirect_service.clone(),
        )
        .await;
        let diagnostic = failed.runtime.last_error().unwrap();
        failed
            .runtime
            .restart(GatewayRuntimeConfig::default(), Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(failed.runtime.status(), ServiceStatus::Stop);
        assert_eq!(failed.runtime.last_error().as_deref(), Some(diagnostic.as_str()));
        failed.rules.delete_rule(bad_match.id).await.unwrap();
        failed.rules.delete_rule(bad_match.id).await.unwrap();
        assert_eq!(failed.runtime.status(), ServiceStatus::Stop);
        assert_eq!(failed.rules.stored_rule_count().await, 2);
        assert!(failed.runtime.last_error().unwrap().contains(&bad_upstream.id.to_string()));
        assert!(!failed.runtime.last_error().unwrap().contains("private-"));
        failed.rules.delete_rule(bad_upstream.id).await.unwrap();
        assert_eq!(failed.runtime.status(), ServiceStatus::Stop);
        assert_eq!(failed.rules.stored_rule_count().await, 1);
        assert!(failed.runtime.last_error().is_none());
        failed.rules.delete_rule(bad_upstream.id).await.unwrap();
        assert!(failed.rules.find_rule(bad_match.id).await.unwrap().is_none());
        assert_eq!(
            failed.rules.dns_redirect_service.list_dynamic_batches().await[0].records.len(),
            1
        );

        failed
            .runtime
            .restart(GatewayRuntimeConfig::default(), Duration::from_secs(1))
            .await
            .unwrap();
        assert!(failed.runtime.last_error().is_none());
        assert_eq!(failed.rules.routes.load().len(), 1);
        failed.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        initial.runtime.shutdown_and_wait(Duration::from_secs(1)).await.unwrap();
        certs.shutdown_and_wait(Duration::from_secs(1)).await;
    }
}
