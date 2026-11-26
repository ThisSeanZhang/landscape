use super::LandscapeConfig;
use toml::{Table, Value};

/// TOML's formatted errors include source lines and values, which can contain credentials.
pub fn config_toml_diagnostic(content: &str, span: Option<std::ops::Range<usize>>) -> String {
    if let Some(prefix) = span.and_then(|range| content.as_bytes().get(..range.start)) {
        let line = 1 + prefix.iter().filter(|&&byte| byte == b'\n').count();
        format!("Invalid configuration TOML on line {line}")
    } else {
        "Invalid configuration TOML".into()
    }
}

impl LandscapeConfig {
    /// Decode an editable block together with the legacy keys that supply its defaults.
    /// Use the normal deserializer so nested settings keep their precedence over flat keys.
    pub fn from_file_section(document: &Table, path: &[&str]) -> Result<Self, toml::de::Error> {
        let mut selected = Table::new();
        let Some(&name) = path.first() else {
            return selected.try_into();
        };
        if let Some(value) = document.get(name) {
            let mut value = value.clone();
            if let ([parent, block], Some(table)) = (path, value.as_table_mut()) {
                table.retain(|key, _| {
                    key == *block
                        || match *parent {
                            "dns" if *block == "cache" => {
                                matches!(key, "cache_capacity" | "cache_ttl" | "negative_cache_ttl")
                            }
                            "dns" => matches!(key, "doh_listen_port" | "doh_http_endpoint"),
                            "metric" => match key {
                                "mode"
                                | "write_flush_interval_secs"
                                | "cleanup_interval_secs"
                                | "cleanup_time_budget_secs"
                                | "cleanup_slice_window_secs" => true,
                                "write_batch_size" => *block == "connect",
                                key => {
                                    (*block == "connect" && key.starts_with("connect_"))
                                        || (*block == "dns" && key.starts_with("dns_"))
                                }
                            },
                            _ => false,
                        }
                });
            }
            selected.insert(name.to_owned(), value);
        }
        if name == "lan_hostname"
            && !selected.contains_key(name)
            && let Some(legacy) = document.get("hostname_registry")
        {
            selected.insert(name.into(), legacy.clone());
        }
        if name == "self_monitor"
            && selected.get(name).and_then(|v| v.get("history_enabled")).is_none()
            && let Some(mode) = document.get("metric").and_then(|v| v.get("mode"))
        {
            selected.insert(
                "metric".into(),
                Value::Table(Table::from_iter([("mode".into(), mode.clone())])),
            );
        }
        selected.try_into()
    }

    pub(super) fn parse_for_startup(content: &str) -> Result<Self, toml::de::Error> {
        let document: Table = toml::from_str(content)?;
        // Valid files need just one decode. Only isolate blocks if a type is wrong.
        if let Ok(config) = document.clone().try_into() {
            return Ok(config);
        }
        let mut config = Self::default();
        macro_rules! load {
            ($($field:ident).+) => {{
                let path = &[$(stringify!($field)),+];
                match Self::from_file_section(&document, path) {
                    Ok(block) => config.$($field).+ = block.$($field).+,
                    Err(_) => super::runtime::warn_repair(&path.join("."), "TOML", "invalid field type", "using block defaults", "default"),
                }
            }};
        }
        load!(auth.admin_user);
        load!(auth.admin_pass);
        load!(web);
        load!(log);
        load!(store);
        load!(dns.cache);
        load!(dns.doh);
        load!(metric.connect);
        load!(metric.dns);
        load!(self_monitor);
        load!(lan_hostname);
        load!(ui);
        load!(time);
        load!(gateway);
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_preserves_valid_credentials_and_independent_legacy_settings() {
        let config = LandscapeConfig::parse_for_startup(
            r#"
            [auth]
            admin_pass = "configured"
            [metric]
            mode = "persistent"
            [metric.connect]
            enabled = "incorrect type"
            [metric.dns]
            retention_days = 7
            [dns]
            doh_listen_port = 8443
            [dns.cache]
            capacity = "incorrect type"
            [hostname_registry]
            lan_suffix = "home.arpa"
        "#,
        )
        .unwrap();
        assert_eq!(config.auth.admin_pass.as_deref(), Some("configured"));
        assert_eq!(config.metric.dns.retention_days, Some(7));
        assert_eq!(config.self_monitor.history_enabled, Some(true));
        assert_eq!(config.dns.doh.listen_port, Some(8443));
        assert_eq!(config.lan_hostname.lan_suffix.as_deref(), Some("home.arpa"));
        assert!(config.dns.cache.capacity.is_none());
    }
}
