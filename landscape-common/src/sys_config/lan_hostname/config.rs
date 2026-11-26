use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeLanHostnameConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub enable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(required = false, nullable = false))]
    pub lan_suffix: Option<String>,
}

#[cfg(test)]
mod tests {
    use crate::error::LdApiErrorInfo;
    use crate::sys_config::LandscapeConfig;

    use super::LandscapeLanHostnameConfig;
    use crate::sys_config::lan_hostname::normalize_lan_suffix;
    use crate::sys_config::{LanHostnameError, RuntimeConfigSource};

    #[test]
    fn legacy_hostname_registry_key_deserializes_as_lan_hostname() {
        let config: LandscapeConfig = toml::from_str(
            r#"
                [hostname_registry]
                lan_suffix = "home"
            "#,
        )
        .unwrap();

        assert_eq!(config.lan_hostname.lan_suffix.as_deref(), Some("home"));
    }

    #[test]
    fn legacy_and_canonical_keys_cannot_be_combined() {
        let config = toml::from_str::<LandscapeConfig>(
            r#"
                [hostname_registry]
                lan_suffix = "legacy"

                [lan_hostname]
                lan_suffix = "canonical"
            "#,
        );

        assert!(config.is_err());
    }

    #[test]
    fn serialization_uses_only_lan_hostname_key() {
        let config = LandscapeConfig {
            lan_hostname: LandscapeLanHostnameConfig {
                lan_suffix: Some("home".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let serialized = toml::to_string(&config).unwrap();

        assert!(serialized.contains("[lan_hostname]"));
        assert!(!serialized.contains("[hostname_registry]"));
    }

    #[test]
    fn runtime_config_updates_from_file_config() {
        let runtime = (LandscapeLanHostnameConfig {
            lan_suffix: Some("home".to_string()),
            ..Default::default()
        })
        .to_runtime()
        .unwrap();

        assert!(runtime.enable);
        assert_eq!(runtime.lan_suffix, "home");
    }

    #[test]
    fn runtime_config_uses_default_when_suffix_is_omitted() {
        let runtime = (LandscapeLanHostnameConfig::default()).to_runtime().unwrap();

        assert!(runtime.enable);
        assert_eq!(runtime.lan_suffix, crate::DEFAULT_DNS_LAN_SUFFIX);
    }

    #[test]
    fn runtime_config_can_disable_lan_hostname_resolution() {
        let runtime = (LandscapeLanHostnameConfig {
            enable: Some(false),
            lan_suffix: Some("home".to_string()),
        })
        .to_runtime()
        .unwrap();

        assert!(!runtime.enable);
        assert_eq!(runtime.lan_suffix, "home");
    }

    #[test]
    fn empty_lan_suffix_uses_default() {
        let config = LandscapeLanHostnameConfig {
            enable: Some(true),
            lan_suffix: Some("   ".to_string()),
        };
        let runtime = config.to_runtime().unwrap();
        assert_eq!(runtime.lan_suffix, crate::DEFAULT_DNS_LAN_SUFFIX);
    }

    #[test]
    fn normalizes_lan_suffix_to_ascii_lowercase_domain() {
        assert_eq!(normalize_lan_suffix(" BÜCHER. ").unwrap(), "xn--bcher-kva");
        assert_eq!(normalize_lan_suffix("LAN").unwrap(), "lan");
        assert_eq!(normalize_lan_suffix(".Home.ARPA.").unwrap(), "home.arpa");
    }

    #[test]
    fn empty_lan_suffix_remains_empty() {
        assert_eq!(normalize_lan_suffix("   ").unwrap(), "");
    }

    #[test]
    fn accepts_multi_label_lan_suffix() {
        assert_eq!(normalize_lan_suffix("home.arpa").unwrap(), "home.arpa");
    }

    #[test]
    fn rejects_empty_labels() {
        let error = normalize_lan_suffix("home..arpa").unwrap_err();

        assert!(matches!(error, LanHostnameError::EmptyLabel { .. }));
        assert_eq!(error.error_id(), "lan_hostname.invalid_suffix.empty_label");
    }

    #[test]
    fn reports_specific_lan_suffix_validation_errors() {
        let invalid_idna = normalize_lan_suffix("\u{200d}").unwrap_err();
        assert!(matches!(invalid_idna, LanHostnameError::InvalidIdna { .. }));
        assert_eq!(invalid_idna.error_id(), "lan_hostname.invalid_suffix.invalid_idna");

        let too_long = normalize_lan_suffix(&"a".repeat(64)).unwrap_err();
        assert!(matches!(too_long, LanHostnameError::TooLong { .. }));
        assert_eq!(too_long.error_id(), "lan_hostname.invalid_suffix.too_long");

        let long_domain = (0..4).map(|_| "a".repeat(63)).collect::<Vec<_>>().join(".");
        let too_long = normalize_lan_suffix(&long_domain).unwrap_err();
        assert!(matches!(too_long, LanHostnameError::TooLong { .. }));

        let invalid_hyphen = normalize_lan_suffix("-lan").unwrap_err();
        assert!(matches!(invalid_hyphen, LanHostnameError::InvalidHyphen { .. }));
        assert_eq!(invalid_hyphen.error_id(), "lan_hostname.invalid_suffix.invalid_hyphen");

        let invalid_character = normalize_lan_suffix("lan_name").unwrap_err();
        assert!(matches!(invalid_character, LanHostnameError::InvalidCharacter { .. }));
        assert_eq!(invalid_character.error_id(), "lan_hostname.invalid_suffix.invalid_character");
    }

    #[test]
    fn rejects_suffixes_reserved_by_the_dns_resolver() {
        for suffix in [
            "invalid",
            "corp.test",
            "service.onion",
            "localhost",
            "corp.localhost",
            "local",
            "office.local",
            "arpa",
            "in-addr.arpa",
            "corp.in-addr.arpa",
            "ip6.arpa",
            "corp.ip6.arpa",
            "resolver.arpa",
            "corp.resolver.arpa",
            "ipv4only.arpa",
            "corp.ipv4only.arpa",
        ] {
            let error = normalize_lan_suffix(suffix).unwrap_err();

            assert!(matches!(error, LanHostnameError::Reserved { .. }));
            assert_eq!(error.error_id(), "lan_hostname.invalid_suffix.reserved");
        }
    }

    #[test]
    fn accepts_non_reserved_arpa_suffixes() {
        for suffix in ["home.arpa", "mylan.arpa", "in-addr.home.arpa"] {
            assert_eq!(normalize_lan_suffix(suffix).unwrap(), suffix);
        }
    }
}
