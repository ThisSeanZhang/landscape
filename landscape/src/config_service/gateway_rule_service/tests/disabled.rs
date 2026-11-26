use super::*;

#[tokio::test]
async fn rules_compile_without_a_server_and_leave_gateway_dns_empty() {
    let (service, certs, _events) = service().await;
    let saved = service.rules.save_rule(rule()).await.unwrap();
    assert_eq!(service.rules.routes.load().len(), 1);
    assert_eq!(service.rules.find_rule(saved.id).await.unwrap().unwrap().domains, saved.domains);
    service
        .rules
        .dns_redirect_service
        .set_dynamic_batch(build_gateway_dynamic_dns_redirect_batch(std::slice::from_ref(&saved)))
        .await;
    assert_eq!(service.rules.dns_redirect_service.list_dynamic_batches().await.len(), 1);
    service.rules.sync_dynamic_dns_redirects().await;
    assert!(service.rules.dns_redirect_service.list_dynamic_batches().await.is_empty());
    assert!(matches!(
        service.runtime.restart(Default::default(), Duration::from_secs(1)).await,
        Err(GatewayError::Unsupported)
    ));
    service.rules.delete_rule(saved.id).await.unwrap();
    assert!(service.rules.routes.load().is_empty());
    certs.shutdown_and_wait(Duration::from_secs(1)).await;
}
