use landscape::dns::{rule_service::DNSRuleService, upstream_service::DnsUpstreamService};
use landscape_common::dns::rule::DnsRuleError;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;
use uuid::Uuid;

async fn dns_rule_service() -> DNSRuleService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    let (dns_events_tx, _dns_events_rx) = mpsc::channel(8);
    let upstream_service = DnsUpstreamService::new(provider.clone(), dns_events_tx.clone()).await;
    DNSRuleService::new(provider, dns_events_tx, upstream_service).await.unwrap()
}

#[tokio::test]
async fn find_required_maps_missing_config_to_domain_not_found() {
    let service = dns_rule_service().await;
    let id = Uuid::new_v4();

    assert!(
        matches!(service.find_required(id).await, Err(DnsRuleError::NotFound(found)) if found == id)
    );
}

#[tokio::test]
async fn delete_required_maps_missing_config_to_domain_not_found() {
    let service = dns_rule_service().await;
    let id = Uuid::new_v4();

    assert!(
        matches!(service.delete_required(id).await, Err(DnsRuleError::NotFound(found)) if found == id)
    );
}
