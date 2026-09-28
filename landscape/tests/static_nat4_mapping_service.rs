use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;

use landscape::config_service::static_nat4_mapping_service::StaticNat4MappingService;
use landscape_common::config_service::static_nat::config::StaticMapPair;
use landscape_common::config_service::static_nat::config4::{
    RuntimeStaticNatMappingV4Config, StaticNatMappingV4Config, StaticNatV4Target,
};
use landscape_common::config_service::static_nat::config6::RuntimeStaticNatMappingV6Config;
use landscape_common::database::error::DbError;
use landscape_common::ebpf::DataplaneGuard;
use landscape_common::event::hub::EnrolledDeviceEventReader;
use landscape_common::service::controller::ConfigStoreController;
use landscape_common::wan_service::nat::config::NatConfig;
use landscape_common::wan_service::nat::dataplane::NatDataplane;
use landscape_database::provider::LandscapeDBServiceProvider;
use uuid::Uuid;

/// Records the size of every synced v4 rule set so tests can observe the
/// `notify_changed` -> `refresh_runtime_rules` -> dataplane wiring.
#[derive(Default)]
struct RecordingNatDataplane {
    sync4_counts: Mutex<Vec<usize>>,
}

impl NatDataplane for RecordingNatDataplane {
    fn attach(
        &self,
        _ifindex: u32,
        _has_mac: bool,
        _config: &NatConfig,
    ) -> Result<Box<dyn DataplaneGuard>, String> {
        Ok(Box::new(()))
    }

    fn sync_static_nat4(&self, configs: &[RuntimeStaticNatMappingV4Config]) {
        self.sync4_counts.lock().unwrap().push(configs.len());
    }

    fn sync_static_nat6(&self, _configs: &[RuntimeStaticNatMappingV6Config]) {}
}

fn mapping_config() -> StaticNatMappingV4Config {
    StaticNatMappingV4Config {
        id: Uuid::new_v4(),
        name: None,
        enable: true,
        remark: "test mapping".to_string(),
        wan_iface_name: None,
        mapping_pair_ports: vec![StaticMapPair { wan_port: 9090, lan_port: 9090 }],
        lan_target: Some(StaticNatV4Target::address(Ipv4Addr::new(192, 168, 1, 100))),
        l4_protocols: vec![6],
        update_at: 0.0,
    }
}

async fn static_nat4_service() -> (StaticNat4MappingService, Arc<RecordingNatDataplane>) {
    let provider = LandscapeDBServiceProvider::mem_test_db().await;
    let (_device_tx, device_rx) = tokio::sync::broadcast::channel(8);
    let device_reader = EnrolledDeviceEventReader::new(device_rx);
    let dataplane = Arc::new(RecordingNatDataplane::default());
    let service = StaticNat4MappingService::new(
        provider,
        device_reader,
        dataplane.clone() as Arc<dyn NatDataplane>,
    )
    .await;
    (service, dataplane)
}

#[tokio::test]
async fn seeds_default_rules_on_empty_db() {
    let (service, dataplane) = static_nat4_service().await;

    let rules = service.list().await.unwrap();
    assert!(!rules.is_empty(), "default DHCPv4 client mapping should be seeded");

    // Startup performs exactly one runtime refresh (no writes happened).
    assert_eq!(dataplane.sync4_counts.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn stale_checked_set_maps_to_conflict() {
    let (service, _dataplane) = static_nat4_service().await;
    let config = mapping_config();

    let saved = service.checked_set(config.clone()).await.unwrap();
    assert!(saved.update_at >= config.update_at);

    let stale = service.checked_set(config).await;
    assert!(matches!(stale, Err(DbError::Conflict)));
}

#[tokio::test]
async fn checked_set_list_is_atomic_and_notifies_once() {
    let (service, dataplane) = static_nat4_service().await;

    let before = service.list().await.unwrap().len();
    let saved = service.checked_set_list(vec![mapping_config(), mapping_config()]).await;
    assert!(saved.is_ok());

    let after = service.list().await.unwrap().len();
    assert_eq!(after, before + 2);

    // Batch write notifies exactly one runtime refresh.
    let syncs = dataplane.sync4_counts.lock().unwrap().len();
    assert_eq!(syncs, 2, "startup refresh + one batch refresh");
}

#[tokio::test]
async fn delete_returns_old_then_none() {
    let (service, _dataplane) = static_nat4_service().await;

    let missing = service.delete(Uuid::new_v4()).await.unwrap();
    assert!(missing.is_none());

    let saved = service.checked_set(mapping_config()).await.unwrap();
    let deleted = service.delete(saved.id).await.unwrap();
    assert!(deleted.is_some());
    assert_eq!(deleted.unwrap().id, saved.id);

    let gone = service.find_by_id(saved.id).await.unwrap();
    assert!(gone.is_none());
}
