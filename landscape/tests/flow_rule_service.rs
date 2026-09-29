use std::sync::Arc;
use std::time::Duration;

use landscape::flow::rule_service::FlowRuleService;
use landscape_common::database::error::DbError;
use landscape_common::event::hub::EnrolledDeviceEventReader;
use landscape_common::event::{dns::DnsEvent, route::RouteEvent};
use landscape_common::flow::config::FlowConfig;
use landscape_common::flow::dataplane::NoopFlowRuleDataplane;
use landscape_common::service::controller::ConfigStoreController;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;
use uuid::Uuid;

fn flow_config(flow_id: u32) -> FlowConfig {
    FlowConfig {
        id: Uuid::new_v4(),
        enable: true,
        flow_id,
        flow_match_rules: Vec::new(),
        flow_targets: Vec::new(),
        name: String::new(),
        remark: "test flow".to_string(),
        update_at: 0.0,
    }
}

async fn flow_rule_service()
-> (FlowRuleService, mpsc::Receiver<DnsEvent>, mpsc::Receiver<RouteEvent>) {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    let (dns_events_tx, dns_events_rx) = mpsc::channel(8);
    let (route_events_tx, route_events_rx) = mpsc::channel(8);
    let (_device_tx, device_rx) = tokio::sync::broadcast::channel(8);
    let device_reader = EnrolledDeviceEventReader::new(device_rx);
    let service = FlowRuleService::new(
        provider,
        dns_events_tx,
        route_events_tx,
        device_reader,
        Arc::new(NoopFlowRuleDataplane),
    )
    .await;
    (service, dns_events_rx, route_events_rx)
}

#[tokio::test]
async fn find_missing_rule_returns_none() {
    let (service, _dns_rx, _route_rx) = flow_rule_service().await;

    let result = service.find_by_id(Uuid::new_v4()).await;
    assert!(matches!(result, Ok(None)));
}

#[tokio::test]
async fn stale_checked_set_maps_to_conflict() {
    let (service, _dns_rx, _route_rx) = flow_rule_service().await;
    let config = flow_config(1);

    let saved = service.checked_set(config.clone()).await.unwrap();
    assert!(saved.update_at >= config.update_at);

    // Echo the original (stale) update_at: the stored row has been refreshed.
    let stale = service.checked_set(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));
}

#[tokio::test]
async fn delete_missing_returns_none_and_delete_existing_returns_old() {
    let (service, _dns_rx, _route_rx) = flow_rule_service().await;

    let missing = service.delete(Uuid::new_v4()).await.unwrap();
    assert!(missing.is_none());

    let saved = service.checked_set(flow_config(2)).await.unwrap();
    let deleted = service.delete(saved.id).await.unwrap();
    assert!(deleted.is_some());
    assert_eq!(deleted.unwrap().id, saved.id);

    let gone = service.find_by_id(saved.id).await.unwrap();
    assert!(gone.is_none());
}

#[tokio::test]
async fn writes_refresh_flow_matches_and_notify_route_event() {
    let (service, mut dns_rx, mut route_rx) = flow_rule_service().await;

    // Startup refresh announces the (empty) flow set once.
    let startup =
        tokio::time::timeout(Duration::from_secs(5), dns_rx.recv()).await.unwrap().unwrap();
    assert!(matches!(startup, DnsEvent::FlowUpdated));

    let saved = service.checked_set(flow_config(3)).await.unwrap();

    // notify_changed runs refresh_flow_matches (FlowUpdated) and then emits a
    // scoped RouteEvent carrying the written flow id.
    let dns_event =
        tokio::time::timeout(Duration::from_secs(5), dns_rx.recv()).await.unwrap().unwrap();
    assert!(matches!(dns_event, DnsEvent::FlowUpdated));

    let route_event =
        tokio::time::timeout(Duration::from_secs(5), route_rx.recv()).await.unwrap().unwrap();
    assert!(
        matches!(route_event, RouteEvent::FlowRuleUpdate { flow_id: Some(id) } if id == saved.flow_id)
    );
}
