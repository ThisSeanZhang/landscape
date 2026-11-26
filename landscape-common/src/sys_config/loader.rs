use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
};

use super::{
    AuthRuntimeConfig, LandscapeConfig, LogRuntimeConfig, RuntimeConfig, RuntimeConfigSource,
    StoreRuntimeConfig, WebRuntimeConfig,
};
use crate::args::WebCommArgs;
use crate::{
    LAND_CONFIG, LANDSCAPE_CONFIG_DIR_NAME, LANDSCAPE_LOG_DIR_NAME, LANDSCAPE_WEBROOT_DIR_NAME,
};

fn default_home_path() -> PathBuf {
    match homedir::my_home() {
        Ok(Some(path)) => path.join(LANDSCAPE_CONFIG_DIR_NAME),
        Ok(None) | Err(_) => {
            tracing::warn!(
                "unable to determine the user home directory; using a local config path"
            );
            PathBuf::from(LANDSCAPE_CONFIG_DIR_NAME)
        }
    }
}

const fn default_debug_mode() -> bool {
    #[cfg(debug_assertions)]
    {
        true
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

fn read_home_config_file(home_path: PathBuf) -> LandscapeConfig {
    let config_path = home_path.join(LAND_CONFIG);
    if config_path.exists() && config_path.is_file() {
        let config_raw = match std::fs::read_to_string(&config_path) {
            Ok(config_raw) => config_raw,
            Err(error) => {
                tracing::error!(
                    path = %config_path.display(),
                    %error,
                    "failed to read landscape config; falling back to defaults (verify key settings such as database path)"
                );
                return LandscapeConfig::default();
            }
        };
        match LandscapeConfig::parse_for_startup(&config_raw) {
            Ok(config) => config,
            Err(error) => {
                tracing::error!(
                    path = %config_path.display(),
                    error = %super::config_toml_diagnostic(&config_raw, error.span()),
                    "failed to parse landscape config; falling back to defaults (verify key settings such as database path)"
                );
                LandscapeConfig::default()
            }
        }
    } else {
        LandscapeConfig::default()
    }
}

impl RuntimeConfig {
    pub fn new(args: WebCommArgs) -> Self {
        Self::new_with_file_config(args, None)
    }

    pub fn new_with_file_config(args: WebCommArgs, file_config: Option<LandscapeConfig>) -> Self {
        fn read_value<T: Clone>(a: &Option<T>, b: &Option<T>, default: T) -> T {
            a.clone().or_else(|| b.clone()).unwrap_or(default)
        }

        let mut home_path = args.config_dir.unwrap_or(default_home_path());

        if home_path.is_relative() {
            let current_dir = std::env::current_dir().unwrap_or_else(|error| {
                tracing::warn!(%error, "failed to determine current directory; using relative config path");
                PathBuf::from(".")
            });
            home_path = current_dir.join(home_path);
            home_path = home_path.components().collect();
        }

        let config = file_config.unwrap_or_else(|| read_home_config_file(home_path.clone()));

        let auth = AuthRuntimeConfig {
            admin_user: read_value(&args.admin_user, &config.auth.admin_user, "root".to_string()),
            admin_pass: read_value(&args.admin_pass, &config.auth.admin_pass, "root".to_string()),
        };

        let default_log_path = home_path.join(LANDSCAPE_LOG_DIR_NAME);
        let log = LogRuntimeConfig {
            log_path: read_value(&args.log_path, &config.log.log_path, default_log_path),
            debug: read_value(&args.debug, &config.log.debug, default_debug_mode()),
            log_output_in_terminal: read_value(
                &args.log_output_in_terminal,
                &config.log.log_output_in_terminal,
                default_debug_mode(),
            ),
            max_log_files: read_value(&args.max_log_files, &config.log.max_log_files, 7),
            log_filter: args.log_filter.clone(),
        };

        let default_web_path = home_path.join(LANDSCAPE_WEBROOT_DIR_NAME);
        let web = WebRuntimeConfig {
            web_root: read_value(&args.web, &config.web.web_root, default_web_path),
            port: read_value(&args.port, &config.web.port, 6300),
            https_port: read_value(&args.https_port, &config.web.https_port, 6443),
            address: read_value(
                &args.address,
                &config.web.address,
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ),
        };

        let store = StoreRuntimeConfig {
            database_path: args
                .database_path
                .clone()
                .or_else(|| config.store.database_path.clone())
                .unwrap_or_else(|| StoreRuntimeConfig::create_default_db_store(&home_path)),
        };

        let metric_connect = config.metric.connect.build_runtime();
        let metric_dns = config.metric.dns.build_runtime();
        let self_monitor = config.self_monitor.build_runtime();
        let dns_cache = config.dns.cache.build_runtime();
        let doh = config.dns.doh.build_runtime();
        let lan_hostname = config.lan_hostname.build_runtime();
        let time = config.time.build_runtime();

        let gateway = config.gateway.build_runtime();

        RuntimeConfig {
            home_path,
            admin_password_overridden: args.admin_pass.is_some(),
            auth,
            log,
            web,
            store,
            metric_connect,
            metric_dns,
            self_monitor,
            dns_cache,
            doh,
            lan_hostname,
            ui: config.ui.clone(),
            time,
            gateway,
            file_config: config,
            auto: args.auto,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::{
        args::WebCommArgs,
        sys_config::{
            LandscapeConfig, LandscapeLanHostnameConfig, RuntimeConfig, web::LandscapeWebConfig,
        },
    };

    #[test]
    fn new_with_file_config_uses_supplied_config_and_keeps_cli_precedence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let init_config = LandscapeConfig {
            web: LandscapeWebConfig {
                port: Some(7000),
                address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ..Default::default()
            },
            ..Default::default()
        };
        let args = WebCommArgs {
            config_dir: Some(temp_dir.path().to_path_buf()),
            port: Some(8000),
            ..Default::default()
        };

        let config = RuntimeConfig::new_with_file_config(args, Some(init_config));

        assert_eq!(config.web.port, 8000);
        assert_eq!(config.web.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn new_with_file_config_reads_landscape_toml_without_supplied_config() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config_path = temp_dir.path().join(crate::LAND_CONFIG);
        std::fs::write(
            config_path,
            r#"
                [web]
                port = 7001
                address = "::1"
            "#,
        )
        .unwrap();
        let args = WebCommArgs {
            config_dir: Some(temp_dir.path().to_path_buf()),
            ..Default::default()
        };

        let config = RuntimeConfig::new_with_file_config(args, None);

        assert_eq!(config.web.port, 7001);
        assert_eq!(config.web.address, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn new_with_file_config_disables_invalid_suffix_and_keeps_source() {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = RuntimeConfig::new_with_file_config(
            WebCommArgs {
                config_dir: Some(temp_dir.path().to_path_buf()),
                ..Default::default()
            },
            Some(LandscapeConfig {
                lan_hostname: LandscapeLanHostnameConfig {
                    enable: Some(true),
                    lan_suffix: Some("corp.test".to_string()),
                },
                ..Default::default()
            }),
        );

        assert!(!config.lan_hostname.enable);
        assert_eq!(config.lan_hostname.lan_suffix, crate::DEFAULT_DNS_LAN_SUFFIX);
        assert_eq!(config.file_config.lan_hostname.enable, Some(true));
        assert_eq!(config.file_config.lan_hostname.lan_suffix.as_deref(), Some("corp.test"));
    }
    #[test]
    fn invalid_fields_fall_back_independently_and_keep_source_config() {
        use crate::sys_config::{
            LandscapeDnsCacheConfig, LandscapeDnsConfig, LandscapeDohConfig, LandscapeMetricConfig,
            LandscapeTimeConfig,
        };
        let temp_dir = tempfile::tempdir().unwrap();
        let source = LandscapeConfig {
            dns: LandscapeDnsConfig {
                doh: LandscapeDohConfig {
                    listen_port: Some(crate::DNS_LISTEN_PORT),
                    ..Default::default()
                },
                cache: LandscapeDnsCacheConfig { capacity: Some(123), ..Default::default() },
            },
            metric: LandscapeMetricConfig {
                connect: crate::sys_config::ConnectMetricConfig {
                    store: crate::sys_config::MetricStoreConfig {
                        cleanup_time_budget_secs: Some(61),
                        ..Default::default()
                    },
                    write_batch_size: Some(123),
                    ..Default::default()
                },
                ..Default::default()
            },
            time: LandscapeTimeConfig { timeout_secs: Some(7), ..Default::default() },
            ..Default::default()
        };
        let path = temp_dir.path().join(crate::LAND_CONFIG);
        let content = toml::to_string(&source).unwrap();
        std::fs::write(&path, &content).unwrap();
        let runtime = RuntimeConfig::new(WebCommArgs {
            config_dir: Some(temp_dir.path().to_path_buf()),
            ..Default::default()
        });
        assert_eq!(runtime.doh.listen_port, crate::DEFAULT_DNS_DOH_LISTEN_PORT);
        assert_eq!(runtime.dns_cache.cache_capacity, 123);
        assert_eq!(runtime.metric_connect.store.cleanup_time_budget_ms, 60_000);
        assert_eq!(runtime.metric_connect.write_batch_size, 123);
        assert_eq!(runtime.time.timeout_secs, 7);
        assert_eq!(runtime.file_config.dns.cache.capacity, Some(123));
        assert_eq!(runtime.file_config.metric.connect.store.cleanup_time_budget_secs, Some(61));
        assert_eq!(std::fs::read_to_string(path).unwrap(), content);
    }
    #[test]
    fn startup_normalizes_effective_suffix_without_replacing_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = "[lan_hostname]\nenable = true\nlan_suffix = ' .Home.ARPA. '\n";
        let path = dir.path().join(crate::LAND_CONFIG);
        std::fs::write(&path, source).unwrap();
        let config = RuntimeConfig::new(WebCommArgs {
            config_dir: Some(dir.path().to_path_buf()),
            ..Default::default()
        });
        assert!(config.lan_hostname.enable);
        assert_eq!(config.lan_hostname.lan_suffix, "home.arpa");
        assert_eq!(config.file_config.lan_hostname.lan_suffix.as_deref(), Some(" .Home.ARPA. "));
        assert_eq!(std::fs::read_to_string(path).unwrap(), source);
    }
}
