use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::{
    args::WebCommArgs,
    config::{LandscapeLanHostnameConfig, RuntimeConfig},
    error::LdError,
    LAND_CONFIG,
};
use landscape_database::provider::LandscapeDBServiceProvider;

async fn config_service(home: &std::path::Path) -> LandscapeConfigService {
    let runtime = RuntimeConfig::new(WebCommArgs {
        config_dir: Some(home.to_path_buf()),
        ..Default::default()
    });
    LandscapeConfigService::new(runtime, LandscapeDBServiceProvider::mem_test_db().await).await
}

#[tokio::test]
async fn update_lan_hostname_config_migrates_legacy_key_and_updates_runtime() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(LAND_CONFIG);
    std::fs::write(
        &config_path,
        r#"[hostname_registry]
lan_suffix = "legacy"

[dns]
cache_ttl = 321
"#,
    )
    .unwrap();
    let service = config_service(temp_dir.path()).await;
    let (_, hash) = service.get_lan_hostname_config_from_file().await;

    service
        .update_lan_hostname_config(
            LandscapeLanHostnameConfig {
                enable: Some(false),
                lan_suffix: Some("BÜCHER.".to_string()),
            },
            hash,
        )
        .await
        .unwrap();

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("[lan_hostname]"));
    assert!(content.contains("lan_suffix = \"xn--bcher-kva\""));
    assert!(!content.contains("[hostname_registry]"));
    assert!(content.contains("[dns]"));
    assert!(content.contains("cache_ttl = 321"));
    assert_eq!(
        service.get_lan_hostname_config_from_memory().lan_suffix.as_deref(),
        Some("xn--bcher-kva")
    );
    assert_eq!(service.get_lan_hostname_config_from_memory().enable, Some(false));
    assert!(!service.get_lan_hostname_runtime_config().enable);
    assert_eq!(service.get_lan_hostname_runtime_config().lan_suffix, "xn--bcher-kva");

    let (_, hash) = service.get_lan_hostname_config_from_file().await;
    service.update_lan_hostname_config(LandscapeLanHostnameConfig::default(), hash).await.unwrap();

    assert_eq!(
        service.get_lan_hostname_runtime_config().lan_suffix,
        landscape_common::DEFAULT_DNS_LAN_SUFFIX
    );
    assert!(service.get_lan_hostname_runtime_config().enable);
    let persisted: landscape_common::config::LandscapeConfig =
        toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert!(persisted.lan_hostname.lan_suffix.is_none());
}

#[tokio::test]
async fn update_lan_hostname_config_rejects_stale_hash_without_changing_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(LAND_CONFIG);
    let original = "[lan_hostname]\nlan_suffix = \"lan\"\n";
    std::fs::write(&config_path, original).unwrap();
    let service = config_service(temp_dir.path()).await;

    let result = service
        .update_lan_hostname_config(
            LandscapeLanHostnameConfig {
                lan_suffix: Some("home".to_string()),
                ..Default::default()
            },
            "stale-hash".to_string(),
        )
        .await;

    assert!(matches!(result, Err(LdError::ConfigConflict)));
    assert_eq!(std::fs::read_to_string(config_path).unwrap(), original);
    assert_eq!(service.get_lan_hostname_config_from_memory().lan_suffix.as_deref(), Some("lan"));
    assert_eq!(service.get_lan_hostname_runtime_config().lan_suffix, "lan");
}
