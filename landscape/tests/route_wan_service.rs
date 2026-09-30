use std::sync::Arc;
use std::time::Duration;

use landscape::wan_service::wan_route_service::RouteWanServiceManagerService;
use landscape_common::config_service::iface::{IfaceZoneType, NetworkIfaceConfig};
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::event::hub::EventHub;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::wan_service::wan_route::RouteWanServiceConfig;
use landscape_common::wan_service::wan_route::dataplane::NoopWanRouteDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;

fn route_wan_config(iface: &str, enable: bool) -> RouteWanServiceConfig {
    RouteWanServiceConfig {
        iface_name: iface.to_string(),
        enable,
        update_at: 0.0,
    }
}

async fn route_wan_service() -> RouteWanServiceManagerService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    provider
        .iface_store()
        .upsert(NetworkIfaceConfig::crate_bridge("wan0".to_string(), Some(IfaceZoneType::Wan)))
        .await
        .unwrap();
    let hub = EventHub::new();
    let event_handle = hub.spawn();

    RouteWanServiceManagerService::new(
        provider,
        event_handle.subscribe_iface(),
        Arc::new(NoopWanRouteDataplane),
    )
    .await
    .unwrap()
}

async fn wait_for_status(service: &RouteWanServiceManagerService, iface: &str) -> ServiceStatus {
    for _ in 0..400 {
        if let Some(status) = service.get_all_status().await.get(iface) {
            return status.clone();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("service status for {iface} not observed in time");
}

#[tokio::test]
async fn handle_service_config_persists_and_tracks_service() {
    let service = route_wan_service().await;

    // enable: false reports Disabled (clean stop), so the config persists
    // without touching the dataplane; the entry settles at Disabled.
    let saved = service.handle_service_config(route_wan_config("wan0", false)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert_eq!(service.find_by_id("wan0".to_string()).await.unwrap().unwrap().iface_name, "wan0");
    assert_eq!(wait_for_status(&service, "wan0").await, ServiceStatus::Disabled);
}

#[tokio::test]
async fn stale_handle_service_config_conflicts_and_keeps_stored_config() {
    let service = route_wan_service().await;

    let config = route_wan_config("wan0", false);
    let saved = service.handle_service_config(config.clone()).await.unwrap();

    // Re-submitting the stale (pre-save) version must conflict; the running
    // service is converged back to the stored config by the controller.
    let stale = service.handle_service_config(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));

    let stored = service.find_by_id("wan0".to_string()).await.unwrap().unwrap();
    assert_eq!(stored.update_at, saved.update_at);
}

#[tokio::test]
async fn delete_and_stop_service_roundtrip() {
    let service = route_wan_service().await;

    let missing = service.delete_and_stop_service("wan0".to_string()).await.unwrap();
    assert!(missing.is_none());

    service.handle_service_config(route_wan_config("wan0", false)).await.unwrap();
    wait_for_status(&service, "wan0").await;

    let deleted = service.delete_and_stop_service("wan0".to_string()).await.unwrap();
    assert!(deleted.is_some());
    assert!(service.find_by_id("wan0".to_string()).await.unwrap().is_none());
    assert!(!service.get_all_status().await.contains_key("wan0"));
}
