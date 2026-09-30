use std::sync::Arc;
use std::time::Duration;

use landscape::sys_service::route::IpRouteService;
use landscape::wan_service::nat_service::NatServiceManagerService;
use landscape_common::database::error::DbError;
use landscape_common::event::hub::EventHub;
use landscape_common::event::route::RouteEvent;
use landscape_common::service::ServiceStatus;
use landscape_common::service::controller::{ConfigStoreController, ConfigStoreServiceController};
use landscape_common::sys_service::route_service::dataplane::NoopRouteTableDataplane;
use landscape_common::wan_service::nat::config::{NatConfig, NatServiceConfig};
use landscape_common::wan_service::nat::dataplane::NoopNatDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use tokio::sync::mpsc;

fn nat_config(iface: &str, enable: bool) -> NatServiceConfig {
    NatServiceConfig {
        iface_name: iface.to_string(),
        enable,
        nat_config: NatConfig {
            tcp_range: 1024..65535,
            udp_range: 1024..65535,
            icmp_in_range: 1024..65535,
        },
        update_at: 0.0,
    }
}

async fn nat_manager() -> NatServiceManagerService {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    let hub = EventHub::new();
    let event_handle = hub.spawn();
    let (_route_tx, route_rx) = mpsc::channel::<RouteEvent>(8);
    let route_service = IpRouteService::new(
        route_rx,
        provider.flow_rule_store(),
        Arc::new(NoopRouteTableDataplane),
    );

    NatServiceManagerService::new(
        provider,
        event_handle.subscribe_iface(),
        route_service,
        Arc::new(NoopNatDataplane),
    )
    .await
}

async fn wait_for_status(service: &NatServiceManagerService, iface: &str) -> ServiceStatus {
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
    let service = nat_manager().await;

    // enable: false reports Disabled (clean stop), so the config persists
    // without attaching the eBPF NAT stage.
    let saved = service.handle_service_config(nat_config("wan0", false)).await.unwrap();

    assert!(saved.update_at > 0.0);
    assert_eq!(service.find_by_id("wan0".to_string()).await.unwrap().unwrap().iface_name, "wan0");
    assert_eq!(wait_for_status(&service, "wan0").await, ServiceStatus::Disabled);
}

#[tokio::test]
async fn missing_iface_fails_start_and_rejects_persist() {
    let service = nat_manager().await;

    // enable: true with an iface that does not exist in the test namespace:
    // the starter reports Failed, persist-after-verify rejects the write.
    let result = service.handle_service_config(nat_config("wan0", true)).await;

    assert!(matches!(result, Err(DbError::ServiceStart(_))));
    assert!(service.find_by_id("wan0".to_string()).await.unwrap().is_none());
}

#[tokio::test]
async fn stale_handle_service_config_conflicts_and_keeps_stored_config() {
    let service = nat_manager().await;

    let config = nat_config("wan0", false);
    let saved = service.handle_service_config(config.clone()).await.unwrap();

    // Re-submitting the stale (pre-save) version must conflict; the controller
    // converges the (Disabled) entry back to the stored config.
    let stale = service.handle_service_config(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));

    let stored = service.find_by_id("wan0".to_string()).await.unwrap().unwrap();
    assert_eq!(stored.update_at, saved.update_at);
}

#[tokio::test]
async fn delete_and_stop_service_roundtrip() {
    let service = nat_manager().await;

    let missing = service.delete_and_stop_iface_service("wan0".to_string()).await.unwrap();
    assert!(missing.is_none());

    service.handle_service_config(nat_config("wan0", false)).await.unwrap();
    wait_for_status(&service, "wan0").await;

    let deleted = service.delete_and_stop_iface_service("wan0".to_string()).await.unwrap();
    assert!(deleted.is_some());
    assert!(service.find_by_id("wan0".to_string()).await.unwrap().is_none());
    assert!(!service.get_all_status().await.contains_key("wan0"));
}
