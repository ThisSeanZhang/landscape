use std::{
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
};

use crate::args::WebCommArgs;
use crate::config::runtime::{
    AuthRuntimeConfig, DnsRuntimeConfig, LogRuntimeConfig, MetricRuntimeConfig, RuntimeConfig,
    StoreRuntimeConfig, TimeRuntimeConfig, WebRuntimeConfig,
};
use crate::config::settings::LandscapeConfig;
use crate::gateway::settings::GatewayRuntimeConfig;
use crate::{
    DEFAULT_TIME_ENABLE, DEFAULT_TIME_SAMPLES_PER_SERVER, DEFAULT_TIME_SERVERS,
    DEFAULT_TIME_STEP_THRESHOLD_MS, DEFAULT_TIME_SYNC_INTERVAL_SECS, DEFAULT_TIME_TIMEOUT_SECS,
    LANDSCAPE_CONFIG_DIR_NAME, LANDSCAPE_LOG_DIR_NAME, LANDSCAPE_WEBROOT_DIR_NAME, LAND_CONFIG,
};

fn default_home_path() -> PathBuf {
    let Some(path) = homedir::my_home().unwrap() else {
        panic!("can not get home path");
    };
    path.join(LANDSCAPE_CONFIG_DIR_NAME)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::{
        args::WebCommArgs,
        config::{settings::LandscapeWebConfig, LandscapeConfig, RuntimeConfig},
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
        let config_raw = std::fs::read_to_string(config_path).unwrap();
        toml::from_str(&config_raw).unwrap()
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
            home_path = std::env::current_dir().unwrap().join(home_path);
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
            database_path: read_value(
                &args.database_path,
                &config.store.database_path,
                StoreRuntimeConfig::create_default_db_store(&home_path),
            ),
        };

        let metric = MetricRuntimeConfig {
            mode: config.metric.mode.clone().unwrap_or(crate::DEFAULT_METRIC_MODE),
            connect_second_window_minutes: config
                .metric
                .connect_second_window_minutes
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_SECOND_WINDOW_MINUTES),
            connect_1m_retention_days: config
                .metric
                .connect_1m_retention_days
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1M_RETENTION_DAYS),
            connect_1h_retention_days: config
                .metric
                .connect_1h_retention_days
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1H_RETENTION_DAYS),
            connect_1d_retention_days: config
                .metric
                .connect_1d_retention_days
                .unwrap_or(crate::DEFAULT_METRIC_CONNECT_1D_RETENTION_DAYS),
            dns_retention_days: config
                .metric
                .dns_retention_days
                .unwrap_or(crate::DEFAULT_DNS_METRIC_RETENTION_DAYS),
            write_batch_size: config
                .metric
                .write_batch_size
                .unwrap_or(crate::DEFAULT_METRIC_WRITE_BATCH_SIZE),
            write_flush_interval_secs: config
                .metric
                .write_flush_interval_secs
                .unwrap_or(crate::DEFAULT_METRIC_WRITE_FLUSH_INTERVAL_SECS),
            db_max_memory_mb: config
                .metric
                .db_max_memory_mb
                .unwrap_or(crate::DEFAULT_METRIC_DB_MAX_MEMORY_MB),
            db_max_threads: config
                .metric
                .db_max_threads
                .unwrap_or(crate::DEFAULT_METRIC_DB_MAX_THREADS),
            cleanup_interval_secs: config
                .metric
                .cleanup_interval_secs
                .unwrap_or(crate::DEFAULT_METRIC_CLEANUP_INTERVAL_SECS),
            cleanup_time_budget_ms: config
                .metric
                .cleanup_time_budget_ms
                .unwrap_or(crate::DEFAULT_METRIC_CLEANUP_TIME_BUDGET_MS),
            cleanup_slice_window_secs: config
                .metric
                .cleanup_slice_window_secs
                .unwrap_or(crate::DEFAULT_METRIC_CLEANUP_SLICE_WINDOW_SECS),
        };

        let dns = DnsRuntimeConfig {
            cache_capacity: config.dns.cache_capacity.unwrap_or(crate::DEFAULT_DNS_CACHE_CAPACITY),
            cache_ttl: config.dns.cache_ttl.unwrap_or(crate::DEFAULT_DNS_CACHE_TTL),
            negative_cache_ttl: config
                .dns
                .negative_cache_ttl
                .unwrap_or(crate::DEFAULT_DNS_NEGATIVE_CACHE_TTL),
            doh_listen_port: config
                .dns
                .doh_listen_port
                .unwrap_or(crate::DEFAULT_DNS_DOH_LISTEN_PORT),
            doh_http_endpoint: config
                .dns
                .doh_http_endpoint
                .clone()
                .unwrap_or_else(|| "/dns-query".to_string()),
        };

        let time = TimeRuntimeConfig {
            enabled: config.time.enabled.unwrap_or(DEFAULT_TIME_ENABLE),
            servers: config.time.servers.clone().unwrap_or_else(|| {
                DEFAULT_TIME_SERVERS.iter().map(|server| (*server).to_string()).collect()
            }),
            sync_interval_secs: config
                .time
                .sync_interval_secs
                .unwrap_or(DEFAULT_TIME_SYNC_INTERVAL_SECS),
            timeout_secs: config.time.timeout_secs.unwrap_or(DEFAULT_TIME_TIMEOUT_SECS),
            step_threshold_ms: config
                .time
                .step_threshold_ms
                .unwrap_or(DEFAULT_TIME_STEP_THRESHOLD_MS),
            samples_per_server: config
                .time
                .samples_per_server
                .unwrap_or(DEFAULT_TIME_SAMPLES_PER_SERVER)
                .max(1),
        };

        let gateway = GatewayRuntimeConfig::from_file_config(&config.gateway);

        RuntimeConfig {
            home_path,
            auth,
            log,
            web,
            store,
            metric,
            dns,
            ui: config.ui.clone(),
            time,
            gateway,
            file_config: config,
            auto: args.auto,
        }
    }
}
