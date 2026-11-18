use landscape_common::{
    INIT_FILE_NAME, INIT_LOCK_FILE_NAME, LAND_CONFIG, VERSION,
    args::WebCommArgs,
    config::{InitConfig, InitConfigError},
    config_service::iface::{IfaceZoneType, NetworkIfaceConfig},
    database::store::ConfigStore,
    sys_config::RuntimeConfig,
    sys_service::gateway::{HttpUpstreamRuleConfig, ProxyRequestHeader},
};
use landscape_database::provider::LandscapeDBServiceProvider;

use super::{StartupError, prepare_startup_init};

fn gateway_rule(name: &str) -> HttpUpstreamRuleConfig {
    serde_json::from_value(serde_json::json!({
        "id": uuid::Uuid::new_v4(),
        "name": name,
        "enable": true,
        "domains": [format!("{name}.example.com")],
        "match_rule": { "t": "host" },
        "upstream": {
            "targets": [{ "address": "127.0.0.1", "port": 8080 }]
        }
    }))
    .unwrap()
}

async fn assert_invalid_gateway_import_preserves_existing_state(lock_exists: bool) {
    let home = tempfile::tempdir().unwrap();
    let database_path = home.path().join("existing.sqlite");
    let provider = LandscapeDBServiceProvider::file_test_db(&database_path).await;
    provider
        .iface_store()
        .upsert(NetworkIfaceConfig::crate_bridge(
            "br-original".to_string(),
            Some(IfaceZoneType::Lan),
        ))
        .await
        .unwrap();
    provider.gateway_http_upstream_store().upsert(gateway_rule("original")).await.unwrap();
    // Comparing full persisted rows also verifies that update_at was not refreshed.
    let original_ifaces =
        serde_json::to_value(provider.iface_store().list().await.unwrap()).unwrap();
    let original_rules =
        serde_json::to_value(provider.gateway_http_upstream_store().list().await.unwrap()).unwrap();

    let config_path = home.path().join(LAND_CONFIG);
    let config_contents = b"# Existing configuration must survive a rejected import.\n";
    std::fs::write(&config_path, config_contents).unwrap();
    let lock_path = home.path().join(INIT_LOCK_FILE_NAME);
    let lock_contents = b"existing initialization lock\n";
    if lock_exists {
        std::fs::write(&lock_path, lock_contents).unwrap();
    }

    let mut invalid_rule = gateway_rule("replacement");
    invalid_rule.upstream.request_headers = vec![ProxyRequestHeader {
        name: "bad header".to_string(),
        value: "value".to_string(),
    }];
    let import = InitConfig {
        version: VERSION.to_string(),
        gateway_rules: vec![invalid_rule],
        ifaces: vec![NetworkIfaceConfig::crate_bridge(
            "br-replacement".to_string(),
            Some(IfaceZoneType::Lan),
        )],
        ..Default::default()
    };
    let init_path = home.path().join(INIT_FILE_NAME);
    let init_contents = toml::to_string(&import).unwrap();
    std::fs::write(&init_path, &init_contents).unwrap();

    let runtime = RuntimeConfig::new_with_file_config(
        WebCommArgs {
            config_dir: Some(home.path().to_path_buf()),
            database_path: Some(format!("sqlite://{}?mode=rwc", database_path.display())),
            ..Default::default()
        },
        Some(Default::default()),
    );
    // A disabled gateway must not allow an invalid imported rule to replace
    // other services' persisted configuration and fail on a later startup.
    assert!(!runtime.gateway.enable);
    let result = prepare_startup_init(home.path(), &runtime, Some(import)).await;
    let Err(StartupError::InitConfig(InitConfigError::Invalid { reason })) = result else {
        panic!("invalid gateway import must fail during startup preflight");
    };
    assert!(reason.contains("bad header"), "unexpected import error: {reason}");

    assert_eq!(
        serde_json::to_value(provider.iface_store().list().await.unwrap()).unwrap(),
        original_ifaces
    );
    assert_eq!(
        serde_json::to_value(provider.gateway_http_upstream_store().list().await.unwrap()).unwrap(),
        original_rules
    );
    assert_eq!(std::fs::read(&config_path).unwrap(), config_contents);
    assert_eq!(std::fs::read_to_string(&init_path).unwrap(), init_contents);
    if lock_exists {
        assert_eq!(std::fs::read(&lock_path).unwrap(), lock_contents);
    } else {
        assert!(!lock_path.exists(), "rejected imports must not create the initialization lock");
    }
}

#[tokio::test]
async fn invalid_gateway_startup_import_preserves_database_and_files_without_lock() {
    assert_invalid_gateway_import_preserves_existing_state(false).await;
}

#[tokio::test]
async fn invalid_gateway_startup_import_preserves_database_and_existing_lock() {
    assert_invalid_gateway_import_preserves_existing_state(true).await;
}
