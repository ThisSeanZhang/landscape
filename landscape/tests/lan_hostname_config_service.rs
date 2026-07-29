use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::{
    args::WebCommArgs,
    config::{LandscapeDnsConfig, LandscapeLanHostnameConfig, RuntimeConfig},
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
                lan_suffix: Some("BÜCHER.Home.".to_string()),
            },
            hash,
        )
        .await
        .unwrap();

    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("[lan_hostname]"));
    assert!(content.contains("lan_suffix = \"xn--bcher-kva.home\""));
    assert!(!content.contains("[hostname_registry]"));
    assert!(content.contains("[dns]"));
    assert!(content.contains("cache_ttl = 321"));
    assert_eq!(
        service.get_lan_hostname_config_from_memory().lan_suffix.as_deref(),
        Some("xn--bcher-kva.home")
    );
    assert_eq!(service.get_lan_hostname_config_from_memory().enable, Some(false));
    assert!(!service.get_lan_hostname_runtime_config().enable);
    assert_eq!(service.get_lan_hostname_runtime_config().lan_suffix, "xn--bcher-kva.home");

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

#[tokio::test]
async fn updating_dns_does_not_invalidate_lan_hostname_hash() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(LAND_CONFIG);
    std::fs::write(
        &config_path,
        r#"[dns]
cache_ttl = 60

[lan_hostname]
lan_suffix = "lan"
"#,
    )
    .unwrap();
    let service = config_service(temp_dir.path()).await;
    let (_, dns_hash) = service.get_dns_config_from_file().await;
    let (_, lan_hostname_hash) = service.get_lan_hostname_config_from_file().await;

    service
        .update_dns_config(
            LandscapeDnsConfig { cache_ttl: Some(120), ..Default::default() },
            dns_hash,
        )
        .await
        .unwrap();

    let (_, current_lan_hostname_hash) = service.get_lan_hostname_config_from_file().await;
    assert_eq!(current_lan_hostname_hash, lan_hostname_hash);

    service
        .update_lan_hostname_config(
            LandscapeLanHostnameConfig {
                lan_suffix: Some("home".to_string()),
                ..Default::default()
            },
            lan_hostname_hash,
        )
        .await
        .unwrap();

    let persisted: landscape_common::config::LandscapeConfig =
        toml::from_str(&std::fs::read_to_string(config_path).unwrap()).unwrap();
    assert_eq!(persisted.dns.cache_ttl, Some(120));
    assert_eq!(persisted.lan_hostname.lan_suffix.as_deref(), Some("home"));
}

#[tokio::test]
async fn concurrent_updates_to_different_sections_are_merged() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(LAND_CONFIG);
    std::fs::write(
        &config_path,
        r#"[dns]
cache_ttl = 60

[lan_hostname]
lan_suffix = "lan"
"#,
    )
    .unwrap();
    let service = config_service(temp_dir.path()).await;
    let (_, dns_hash) = service.get_dns_config_from_file().await;
    let (_, lan_hostname_hash) = service.get_lan_hostname_config_from_file().await;

    let dns_service = service.clone();
    let lan_hostname_service = service.clone();
    let (dns_result, lan_hostname_result) = tokio::join!(
        dns_service.update_dns_config(
            LandscapeDnsConfig { cache_ttl: Some(120), ..Default::default() },
            dns_hash,
        ),
        lan_hostname_service.update_lan_hostname_config(
            LandscapeLanHostnameConfig {
                lan_suffix: Some("home".to_string()),
                ..Default::default()
            },
            lan_hostname_hash,
        ),
    );

    dns_result.unwrap();
    lan_hostname_result.unwrap();

    let persisted: landscape_common::config::LandscapeConfig =
        toml::from_str(&std::fs::read_to_string(config_path).unwrap()).unwrap();
    assert_eq!(persisted.dns.cache_ttl, Some(120));
    assert_eq!(persisted.lan_hostname.lan_suffix.as_deref(), Some("home"));
    assert_eq!(service.get_dns_config().0.cache_ttl, Some(120));
    assert_eq!(service.get_lan_hostname_config_from_memory().lan_suffix.as_deref(), Some("home"));
}

#[tokio::test]
async fn concurrent_updates_to_same_section_reject_one_stale_hash() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config_path = temp_dir.path().join(LAND_CONFIG);
    std::fs::write(&config_path, "[dns]\ncache_ttl = 60\n").unwrap();
    let service = config_service(temp_dir.path()).await;
    let (_, dns_hash) = service.get_dns_config_from_file().await;

    let first_service = service.clone();
    let second_service = service.clone();
    let (first_result, second_result) = tokio::join!(
        first_service.update_dns_config(
            LandscapeDnsConfig { cache_ttl: Some(120), ..Default::default() },
            dns_hash.clone(),
        ),
        second_service.update_dns_config(
            LandscapeDnsConfig { cache_ttl: Some(180), ..Default::default() },
            dns_hash,
        ),
    );

    assert_ne!(first_result.is_ok(), second_result.is_ok());
    let conflict = if first_result.is_err() { first_result } else { second_result };
    assert!(matches!(conflict, Err(LdError::ConfigConflict)));

    let persisted: landscape_common::config::LandscapeConfig =
        toml::from_str(&std::fs::read_to_string(config_path).unwrap()).unwrap();
    assert!(matches!(persisted.dns.cache_ttl, Some(120 | 180)));
    assert_eq!(service.get_dns_config().0.cache_ttl, persisted.dns.cache_ttl);
}
