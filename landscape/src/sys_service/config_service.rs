use arc_swap::ArcSwap;
use landscape_common::config::{InitConfig, InitConfigError};
use landscape_common::database::error::DbError;
use landscape_common::database::store::ConfigStore;
use landscape_common::sys_config::{
    AuthRuntimeConfig, CacheRuntimeConfig, ChangePasswordRequest, ConfigUpdateError,
    ConnectMetricConfig, ConnectMetricRuntimeConfig, DnsMetricConfig, DnsMetricRuntimeConfig,
    DohRuntimeConfig, GatewayRuntimeConfig, LanHostnameRuntimeConfig, LandscapeConfig,
    LandscapeDnsCacheConfig, LandscapeDohConfig, LandscapeGatewayConfig,
    LandscapeLanHostnameConfig, LandscapeMetricConfig, LandscapeSelfMonitorConfig,
    LandscapeTimeConfig, LandscapeUiConfig, RuntimeConfig, RuntimeConfigSource,
    SelfMonitorRuntimeConfig, TimeRuntimeConfig, config_toml_diagnostic,
};
use landscape_database::provider::LandscapeDBServiceProvider;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{Mutex, watch};
use toml_edit::DocumentMut;
use uuid::Uuid;

#[derive(Clone)]
pub struct LandscapeConfigService {
    config: Arc<ArcSwap<RuntimeConfig>>,
    store: LandscapeDBServiceProvider,
    connect_metric_tx: watch::Sender<ConnectMetricRuntimeConfig>,
    dns_metric_tx: watch::Sender<DnsMetricRuntimeConfig>,
    self_monitor_tx: watch::Sender<SelfMonitorRuntimeConfig>,
    dns_cache_tx: watch::Sender<CacheRuntimeConfig>,
    doh_tx: watch::Sender<DohRuntimeConfig>,
    auth: Arc<ArcSwap<AuthRuntimeConfig>>,
    lan_hostname: Arc<ArcSwap<LanHostnameRuntimeConfig>>,
    write_lock: Arc<Mutex<()>>,
}

impl LandscapeConfigService {
    pub async fn new(config: RuntimeConfig, store: LandscapeDBServiceProvider) -> Self {
        LandscapeConfigService {
            auth: Arc::new(ArcSwap::from_pointee(config.auth.clone())),
            lan_hostname: Arc::new(ArcSwap::from_pointee(config.lan_hostname.clone())),
            connect_metric_tx: watch::Sender::new(config.metric_connect.clone()),
            dns_metric_tx: watch::Sender::new(config.metric_dns.clone()),
            self_monitor_tx: watch::Sender::new(config.self_monitor.clone()),
            dns_cache_tx: watch::Sender::new(config.dns_cache.clone()),
            doh_tx: watch::Sender::new(config.doh.clone()),
            config: Arc::new(ArcSwap::from_pointee(config)),
            store,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    fn section_hash<T: Serialize>(config: &T) -> Result<String, DbError> {
        let content =
            toml::to_string(config).map_err(|error| DbError::Internal(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        Ok(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn read_content(path: &Path) -> Result<String, DbError> {
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(error) => Err(error.into()),
        }
    }

    fn decode_section(content: &str, path: &[&str]) -> Result<LandscapeConfig, DbError> {
        let document = toml::from_str(content).map_err(|e: toml::de::Error| {
            DbError::Internal(config_toml_diagnostic(content, e.span()))
        })?;
        LandscapeConfig::from_file_section(&document, path)
            .map_err(|_| DbError::Internal(format!("Invalid configuration in {}", path.join("."))))
    }

    fn parse_document(content: &str) -> Result<DocumentMut, DbError> {
        content.parse().map_err(|error: toml_edit::TomlError| {
            DbError::Internal(config_toml_diagnostic(content, error.span()))
        })
    }

    fn set_section<T: Serialize>(
        table: &mut toml_edit::Table,
        name: &str,
        config: &T,
    ) -> Result<(), DbError> {
        let content =
            toml::to_string(config).map_err(|error| DbError::Internal(error.to_string()))?;
        let section = Self::parse_document(&content)?;
        table[name] = section.as_item().clone();
        Ok(())
    }

    // The flat keys can supply defaults to more than one section. Materialize those
    // values before the first independent edit so clearing a field survives restart.
    fn migrate_flat_metric(document: &mut DocumentMut) -> Result<(), DbError> {
        const LEGACY_KEYS: &[&str] = &[
            "mode",
            "connect_second_window_minutes",
            "connect_1m_retention_days",
            "connect_1h_retention_days",
            "connect_1d_retention_days",
            "connect_summary_retention_days",
            "connect_summary_max_rows",
            "connect_db_max_mb",
            "dns_retention_days",
            "dns_1m_retention_days",
            "dns_db_max_mb",
            "write_batch_size",
            "write_flush_interval_secs",
            "cleanup_interval_secs",
            "cleanup_time_budget_secs",
            "cleanup_slice_window_secs",
        ];
        let Some(table) = document.get_mut("metric").and_then(toml_edit::Item::as_table_like_mut)
        else {
            return Ok(());
        };
        let mut history_enabled = None;
        for &key in LEGACY_KEYS {
            let Some(value) = table.get(key) else { continue };
            let mut legacy = DocumentMut::new();
            legacy["metric"][key] = value.clone();
            // Leave an invalid sibling's legacy key intact. Valid keys go through
            // the same compatibility conversion used at startup.
            let Ok(config) = toml::from_str::<LandscapeConfig>(&legacy.to_string()) else {
                continue;
            };
            let serialized = toml::to_string(&config.metric)
                .map_err(|err| DbError::Internal(err.to_string()))?;
            let canonical = Self::parse_document(&serialized)?;
            Self::fill_missing_fields(table, canonical.as_table());
            table.remove(key);
            history_enabled = history_enabled.or(config.self_monitor.history_enabled);
        }
        if let Some(enabled) = history_enabled {
            let section = document
                .entry("self_monitor")
                .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
            if let Some(table) = section.as_table_like_mut()
                && !table.contains_key("history_enabled")
            {
                table.insert("history_enabled", toml_edit::value(enabled));
            }
        }
        Ok(())
    }

    fn fill_missing_fields(
        target: &mut dyn toml_edit::TableLike,
        defaults: &dyn toml_edit::TableLike,
    ) {
        for (name, value) in defaults.iter() {
            match target.get_mut(name) {
                None => {
                    target.insert(name, value.clone());
                }
                Some(current) => {
                    if let (Some(current), Some(defaults)) =
                        (current.as_table_like_mut(), value.as_table_like())
                    {
                        Self::fill_missing_fields(current, defaults);
                    }
                }
            }
        }
    }

    fn write_config_file(path: &Path, content: &str) -> Result<(), DbError> {
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("landscape.toml");
        let tmp_path = path.with_file_name(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        let directory = std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?;
        let result = (|| -> Result<(), DbError> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            let mut tmp_file = options.open(&tmp_path)?;
            tmp_file.write_all(content.as_bytes())?;
            tmp_file.sync_all()?;
            std::fs::rename(&tmp_path, path)?;
            // The new file is already visible. Publish the same runtime even if the
            // filesystem cannot confirm that the rename will survive a power loss.
            if let Err(error) = directory.sync_all() {
                tracing::error!(%error, path = %path.display(), "configuration committed but directory sync failed");
            }
            Ok(())
        })();

        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }

    fn ensure_expected_hash<T: Serialize>(config: &T, expected_hash: &str) -> Result<(), DbError> {
        if Self::section_hash(config)? != expected_hash {
            return Err(DbError::Conflict);
        }
        Ok(())
    }

    fn read_section_from_file<T, Select>(
        &self,
        path: &[&str],
        select: Select,
    ) -> Result<(T, String), DbError>
    where
        T: Serialize,
        Select: FnOnce(LandscapeConfig) -> T,
    {
        let content = Self::read_content(&self.get_config_path())?;
        let config = Self::decode_section(&content, path)?;
        let section = select(config);
        let hash = Self::section_hash(&section)?;
        Ok((section, hash))
    }

    async fn update_section<T, Select, Commit>(
        &self,
        section_path: &[&str],
        aliases: &[&str],
        new_config: T,
        expected_hash: String,
        select: Select,
        commit: Commit,
    ) -> Result<(), DbError>
    where
        T: Serialize,
        Select: for<'a> Fn(&'a LandscapeConfig) -> &'a T,
        Commit: FnOnce(&T),
    {
        let _guard = self.write_lock.lock().await;
        let path = self.get_config_path();
        let content = Self::read_content(&path)?;
        let current_config = Self::decode_section(&content, section_path)?;
        Self::ensure_expected_hash(select(&current_config), &expected_hash)?;

        let mut document = Self::parse_document(&content)?;
        if matches!(section_path.first(), Some(&"metric" | &"self_monitor")) {
            Self::migrate_flat_metric(&mut document)?;
        }
        let (section_name, parents) = section_path.split_last().expect("nonempty section path");
        let mut table = document.as_table_mut();
        for parent in parents {
            let item = table.entry(parent).or_insert(toml_edit::Item::None);
            if !item.is_table() {
                *item =
                    match std::mem::take(item) {
                        toml_edit::Item::None => toml_edit::Item::Table(toml_edit::Table::new()),
                        item => toml_edit::Item::Table(item.into_table().map_err(|_| {
                            DbError::Internal(format!("expected table at {parent}"))
                        })?),
                    };
            }
            table = item.as_table_mut().expect("table initialized above");
        }
        for alias in aliases {
            table.remove(alias);
        }
        Self::set_section(table, section_name, &new_config)?;
        Self::write_config_file(&path, &document.to_string())?;
        commit(&new_config);

        Ok(())
    }

    pub async fn export_init_config(&self) -> Result<InitConfig, InitConfigError> {
        let content = Self::read_content(&self.get_config_path())?;
        let config: LandscapeConfig = toml::from_str(&content)
            .map_err(|error| DbError::Internal(config_toml_diagnostic(&content, error.span())))?;
        Ok(InitConfig {
            version: landscape_common::VERSION.to_string(),
            config,
            ifaces: self.store.iface_store().list().await?,
            marks: self.store.flow_wan_service_store().list().await?,
            wan_links: self.store.wan_link_store().list().await?,
            flow_rules: self.store.flow_rule_store().list().await?,
            dns_rules: self.store.dns_rule_store().list().await?,
            dst_ip_mark: self.store.dst_ip_rule_store().list().await?,
            firewall_rules: self.store.firewall_rule_store().list().await?,
            firewall_blacklists: self.store.firewall_blacklist_store().list().await?,
            wifi_configs: self.store.wifi_service_store().list().await?,
            dhcpv4_services: self.store.dhcp_v4_server_store().list().await?,
            geo_ips: self.store.geo_ip_rule_store().list().await?,
            geo_sites: self.store.geo_site_rule_store().list().await?,
            route_lans: self.store.route_lan_service_store().list().await?,
            route_wans: self.store.route_wan_service_store().list().await?,
            static_nat_mappings_v4: self.store.static_nat_mapping_v4_store().list().await?,
            static_nat_mappings_v6: self.store.static_nat_mapping_v6_store().list().await?,
            dns_redirects: self.store.dns_redirect_rule_store().list().await?,
            dns_upstream_configs: self.store.dns_upstream_config_store().list().await?,
            enrolled_devices: self.store.enrolled_device_store().list().await?,
            lan_ipv6s: self.store.lan_ipv6_v2_service_store().list().await?,
            cert_accounts: self.store.cert_account_store().list().await?,
            certs: self.store.cert_store().list().await?,
            gateway_rules: self.store.gateway_http_upstream_store().list_checked().await?,
            ddns_jobs: self.store.ddns_job_store().list().await?,
            dns_provider_profiles: self.store.dns_provider_profile_store().list().await?,
        })
    }

    pub fn get_ui_config_from_memory(&self) -> LandscapeUiConfig {
        self.config.load().ui.clone()
    }

    pub fn shared_auth(&self) -> Arc<ArcSwap<AuthRuntimeConfig>> {
        self.auth.clone()
    }

    pub fn shared_lan_hostname(&self) -> Arc<ArcSwap<LanHostnameRuntimeConfig>> {
        self.lan_hostname.clone()
    }

    pub fn get_metric_config_from_memory(&self) -> LandscapeMetricConfig {
        self.config.load().file_config.metric.clone()
    }

    pub fn subscribe_connect_metric(&self) -> watch::Receiver<ConnectMetricRuntimeConfig> {
        self.connect_metric_tx.subscribe()
    }

    pub fn subscribe_dns_metric(&self) -> watch::Receiver<DnsMetricRuntimeConfig> {
        self.dns_metric_tx.subscribe()
    }

    pub fn subscribe_self_monitor(&self) -> watch::Receiver<SelfMonitorRuntimeConfig> {
        self.self_monitor_tx.subscribe()
    }

    pub fn subscribe_dns_cache(&self) -> watch::Receiver<CacheRuntimeConfig> {
        self.dns_cache_tx.subscribe()
    }

    pub fn subscribe_doh(&self) -> watch::Receiver<DohRuntimeConfig> {
        self.doh_tx.subscribe()
    }

    pub fn get_lan_hostname_config_from_memory(&self) -> LandscapeLanHostnameConfig {
        self.config.load().file_config.lan_hostname.clone()
    }

    pub fn get_lan_hostname_runtime_config(&self) -> LanHostnameRuntimeConfig {
        self.config.load().lan_hostname.clone()
    }

    pub fn get_time_config_from_memory(&self) -> LandscapeTimeConfig {
        self.config.load().file_config.time.clone()
    }

    pub fn get_time_runtime_config(&self) -> TimeRuntimeConfig {
        self.config.load().time.clone()
    }

    pub fn get_gateway_config_from_memory(&self) -> LandscapeGatewayConfig {
        self.config.load().file_config.gateway.clone()
    }

    pub fn get_gateway_runtime_config(&self) -> GatewayRuntimeConfig {
        self.config.load().gateway.clone()
    }

    pub fn get_time_config_from_file(&self) -> Result<(LandscapeTimeConfig, String), DbError> {
        self.read_section_from_file(&["time"], |config| config.time)
    }

    pub fn get_dns_cache_from_file(&self) -> Result<(LandscapeDnsCacheConfig, String), DbError> {
        self.read_section_from_file(&["dns", "cache"], |config| config.dns.cache)
    }

    pub fn get_doh_from_file(&self) -> Result<(LandscapeDohConfig, String), DbError> {
        self.read_section_from_file(&["dns", "doh"], |config| config.dns.doh)
    }

    pub fn get_lan_hostname_config_from_file(
        &self,
    ) -> Result<(LandscapeLanHostnameConfig, String), DbError> {
        self.read_section_from_file(&["lan_hostname"], |config| config.lan_hostname)
    }

    pub fn get_gateway_config_from_file(
        &self,
    ) -> Result<(LandscapeGatewayConfig, String), DbError> {
        self.read_section_from_file(&["gateway"], |config| config.gateway)
    }

    pub async fn get_ui_config_from_file(&self) -> Result<(LandscapeUiConfig, String), DbError> {
        self.read_section_from_file(&["ui"], |config| config.ui)
    }

    pub fn get_connect_metric_from_file(&self) -> Result<(ConnectMetricConfig, String), DbError> {
        self.read_section_from_file(&["metric", "connect"], |config| config.metric.connect)
    }

    pub fn get_dns_metric_from_file(&self) -> Result<(DnsMetricConfig, String), DbError> {
        self.read_section_from_file(&["metric", "dns"], |config| config.metric.dns)
    }

    pub fn get_self_monitor_from_file(
        &self,
    ) -> Result<(LandscapeSelfMonitorConfig, String), DbError> {
        self.read_section_from_file(&["self_monitor"], |config| config.self_monitor)
    }

    pub fn get_config_path(&self) -> std::path::PathBuf {
        self.config.load().home_path.join(landscape_common::LAND_CONFIG)
    }

    pub async fn update_ui_config(
        &self,
        new_ui: LandscapeUiConfig,
        expected_hash: String,
    ) -> Result<(), DbError> {
        self.update_section(
            &["ui"],
            &[],
            new_ui,
            expected_hash,
            |config| &config.ui,
            |new_ui| {
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.ui = new_ui.clone();
                    new_config.file_config.ui = new_ui.clone();
                    new_config
                });
            },
        )
        .await
    }
    pub async fn update_connect_metric_config(
        &self,
        section: ConnectMetricConfig,
        expected_hash: String,
    ) -> Result<(), ConfigUpdateError> {
        let runtime = section.to_runtime()?;
        self.update_section(
            &["metric", "connect"],
            &[],
            section,
            expected_hash,
            |cfg| &cfg.metric.connect,
            |section| {
                self.config.rcu(|old| {
                    let mut next = (**old).clone();
                    next.file_config.metric.connect = section.clone();
                    next.metric_connect = runtime.clone();
                    next
                });
                self.connect_metric_tx.send_if_modified(|current| {
                    if *current == runtime {
                        return false;
                    }
                    *current = runtime;
                    true
                });
            },
        )
        .await?;
        Ok(())
    }

    pub async fn update_dns_metric_config(
        &self,
        section: DnsMetricConfig,
        expected_hash: String,
    ) -> Result<(), ConfigUpdateError> {
        let runtime = section.to_runtime()?;
        self.update_section(
            &["metric", "dns"],
            &[],
            section,
            expected_hash,
            |cfg| &cfg.metric.dns,
            |section| {
                self.config.rcu(|old| {
                    let mut next = (**old).clone();
                    next.file_config.metric.dns = section.clone();
                    next.metric_dns = runtime.clone();
                    next
                });
                self.dns_metric_tx.send_if_modified(|current| {
                    if *current == runtime {
                        return false;
                    }
                    *current = runtime;
                    true
                });
            },
        )
        .await?;
        Ok(())
    }

    pub async fn update_self_monitor_config(
        &self,
        section: LandscapeSelfMonitorConfig,
        expected_hash: String,
    ) -> Result<(), ConfigUpdateError> {
        let runtime = section.to_runtime()?;
        self.update_section(
            &["self_monitor"],
            &[],
            section,
            expected_hash,
            |cfg| &cfg.self_monitor,
            |section| {
                self.config.rcu(|old| {
                    let mut next = (**old).clone();
                    next.file_config.self_monitor = section.clone();
                    next.self_monitor = runtime.clone();
                    next
                });
                self.self_monitor_tx.send_if_modified(|current| {
                    if *current == runtime {
                        return false;
                    }
                    *current = runtime;
                    true
                });
            },
        )
        .await?;
        Ok(())
    }

    pub async fn update_dns_cache_config(
        &self,
        section: LandscapeDnsCacheConfig,
        expected_hash: String,
    ) -> Result<(), ConfigUpdateError> {
        let runtime = section.to_runtime()?;
        self.update_section(
            &["dns", "cache"],
            &["cache_capacity", "cache_ttl", "negative_cache_ttl", "tcp_enabled"],
            section,
            expected_hash,
            |config| &config.dns.cache,
            |section| {
                self.config.rcu(|old| {
                    let mut next = (**old).clone();
                    next.dns_cache = runtime.clone();
                    next.file_config.dns.cache = section.clone();
                    next
                });
                if *self.dns_cache_tx.borrow() != runtime {
                    self.dns_cache_tx.send_replace(runtime);
                }
            },
        )
        .await?;
        Ok(())
    }

    pub async fn update_doh_config(
        &self,
        section: LandscapeDohConfig,
        expected_hash: String,
    ) -> Result<(), ConfigUpdateError> {
        let runtime = section.to_runtime()?;
        self.update_section(
            &["dns", "doh"],
            &["doh_listen_port", "doh_http_endpoint", "tcp_enabled"],
            section,
            expected_hash,
            |config| &config.dns.doh,
            |section| {
                self.config.rcu(|old| {
                    let mut next = (**old).clone();
                    next.doh = runtime.clone();
                    next.file_config.dns.doh = section.clone();
                    next
                });
                if *self.doh_tx.borrow() != runtime {
                    self.doh_tx.send_replace(runtime);
                }
            },
        )
        .await?;
        Ok(())
    }

    pub async fn update_lan_hostname_config(
        &self,
        new_lan_hostname: LandscapeLanHostnameConfig,
        expected_hash: String,
    ) -> Result<(), ConfigUpdateError> {
        let runtime_lan_hostname = new_lan_hostname.to_runtime()?;
        let mut new_lan_hostname = new_lan_hostname;
        if new_lan_hostname.lan_suffix.is_some() {
            new_lan_hostname.lan_suffix = new_lan_hostname
                .lan_suffix
                .as_ref()
                .filter(|suffix| !suffix.trim().is_empty())
                .map(|_| runtime_lan_hostname.lan_suffix.clone());
        }
        let file_lan_hostname = new_lan_hostname.clone();
        self.update_section(
            &["lan_hostname"],
            &["hostname_registry"],
            new_lan_hostname,
            expected_hash,
            |config| &config.lan_hostname,
            |_| {
                let runtime = runtime_lan_hostname.clone();
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.lan_hostname = runtime.clone();
                    new_config.file_config.lan_hostname = file_lan_hostname.clone();
                    new_config
                });
                self.lan_hostname.store(Arc::new(runtime));
            },
        )
        .await?;
        Ok(())
    }

    pub async fn update_time_config(
        &self,
        new_time: LandscapeTimeConfig,
        expected_hash: String,
        publish: impl FnOnce(TimeRuntimeConfig),
    ) -> Result<(), ConfigUpdateError> {
        let runtime = new_time.to_runtime()?;
        self.update_section(
            &["time"],
            &[],
            new_time,
            expected_hash,
            |config| &config.time,
            |new_time| {
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.time = runtime.clone();
                    new_config.file_config.time = new_time.clone();
                    new_config
                });
                publish(runtime);
            },
        )
        .await?;
        Ok(())
    }

    pub async fn update_gateway_config(
        &self,
        new_gateway: LandscapeGatewayConfig,
        expected_hash: String,
    ) -> Result<(), ConfigUpdateError> {
        let runtime = new_gateway.to_runtime()?;
        self.update_section(
            &["gateway"],
            &[],
            new_gateway,
            expected_hash,
            |config| &config.gateway,
            |new_gateway| {
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.gateway = runtime.clone();
                    new_config.file_config.gateway = new_gateway.clone();
                    new_config
                });
            },
        )
        .await?;
        Ok(())
    }

    pub async fn change_password(
        &self,
        request: ChangePasswordRequest,
    ) -> Result<(), ConfigUpdateError> {
        let _guard = self.write_lock.lock().await;
        let snapshot = self.config.load();
        if snapshot.admin_password_overridden {
            return Err(
                landscape_common::sys_config::auth::api::PasswordChangeError::ManagedExternally
                    .into(),
            );
        }
        request.validate(&snapshot.auth.admin_pass)?;
        let new_password = request.new_password;
        let path = self.get_config_path();
        let content = Self::read_content(&path)?;
        let mut document = Self::parse_document(&content)?;
        let auth = document
            .entry("auth")
            .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()))
            .as_table_like_mut()
            .ok_or_else(|| {
                DbError::Internal("Invalid configuration in auth: expected a table".into())
            })?;
        auth.insert("admin_pass", toml_edit::value(&new_password));
        Self::write_config_file(&path, &document.to_string())?;

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.auth.admin_pass = new_password.clone();
            new_config.file_config.auth.admin_pass = Some(new_password.clone());
            new_config
        });
        self.auth.store(Arc::new(self.config.load().auth.clone()));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::args::WebCommArgs;

    async fn service() -> (tempfile::TempDir, LandscapeConfigService) {
        let dir = tempfile::tempdir().unwrap();
        let runtime = RuntimeConfig::new_with_file_config(
            WebCommArgs {
                config_dir: Some(dir.path().to_path_buf()),
                database_path: Some("sqlite::memory:".into()),
                ..Default::default()
            },
            Some(LandscapeConfig::default()),
        );
        let store = LandscapeDBServiceProvider::mem_test_db().await;
        (dir, LandscapeConfigService::new(runtime, store).await)
    }

    #[tokio::test]
    async fn independent_edits_preserve_invalid_siblings_and_back_up_disk_values() {
        let (_dir, service) = service().await;
        let path = service.get_config_path();
        let source = "[auth]\nadmin_pass = 'from-disk'\n[dns.cache]\ncapacity = 27\n[dns.doh]\nlisten_port = 'invalid'\n";
        std::fs::write(&path, source).unwrap();
        let (mut cache, hash) = service.get_dns_cache_from_file().unwrap();
        assert_eq!(cache.capacity, Some(27));
        cache.capacity = Some(30);
        service.update_dns_cache_config(cache, hash).await.unwrap();
        assert!(service.get_doh_from_file().is_err());
        let saved = std::fs::read_to_string(&path).unwrap();
        assert!(saved.contains("listen_port = 'invalid'"));
        assert!(service.export_init_config().await.is_err());
        std::fs::write(path, saved.replace("'invalid'", "8443")).unwrap();
        let backup = service.export_init_config().await.unwrap();
        assert_eq!(backup.config.auth.admin_pass.as_deref(), Some("from-disk"));
        assert_eq!(backup.config.dns.cache.capacity, Some(30));
        assert_eq!(backup.config.dns.doh.listen_port, Some(8443));
    }

    #[tokio::test]
    async fn config_parse_errors_omit_file_values_and_report_the_location() {
        let (_dir, service) = service().await;
        let path = service.get_config_path();
        for content in [
            "[dns.doh]\nlisten_port = 'private-marker'\n",
            "[auth]\nadmin_pass = 'private-marker' ]\n",
        ] {
            std::fs::write(&path, content).unwrap();
            let edit_error = service.get_doh_from_file().unwrap_err().to_string();
            let export_error = service.export_init_config().await.unwrap_err().to_string();
            assert!(!edit_error.contains("private-marker"));
            assert!(!export_error.contains("private-marker"));
            assert!(edit_error.contains("dns.doh") || edit_error.contains("line 2"));
            assert!(export_error.contains("line 2"));
        }
    }

    #[tokio::test]
    async fn editing_self_monitor_preserves_legacy_metrics_in_each_toml_table_form() {
        let (_dir, service) = service().await;
        let path = service.get_config_path();
        for source in [
            "metric.mode = 'memory'\nmetric.cleanup_interval_secs = 42\nmetric.dns.store.max_mb = 321\n",
            "[metric]\nmode = 'memory'\ncleanup_interval_secs = 42\ndns.store.max_mb = 321\n",
            "metric = { mode = 'memory', cleanup_interval_secs = 42, dns = { store = { max_mb = 321 } } }\n",
        ] {
            std::fs::write(&path, source).unwrap();
            let before: LandscapeConfig = toml::from_str(source).unwrap();
            let (mut monitor, hash) = service.get_self_monitor_from_file().unwrap();
            monitor.history_enabled = Some(true);
            service.update_self_monitor_config(monitor, hash).await.unwrap();
            let saved = std::fs::read_to_string(&path).unwrap();
            let after: LandscapeConfig = toml::from_str(&saved).unwrap();
            assert_eq!(after.metric, before.metric);
            assert_eq!(after.self_monitor.history_enabled, Some(true));
            assert!(!saved.contains("mode ="));
        }
    }

    #[tokio::test]
    async fn metric_migration_keeps_invalid_legacy_keys_owned_by_other_blocks() {
        let (_dir, service) = service().await;
        let path = service.get_config_path();
        std::fs::write(&path, "[metric]\nmode = 'memory'\ndns_retention_days = 'invalid'\n")
            .unwrap();
        let (_, hash) = service.get_connect_metric_from_file().unwrap();
        service.update_connect_metric_config(ConnectMetricConfig::default(), hash).await.unwrap();
        let saved: toml::Table = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(saved["metric"]["dns_retention_days"].as_str(), Some("invalid"));
        assert_eq!(saved["metric"]["dns"]["enabled"].as_bool(), Some(true));
        assert!(service.get_dns_metric_from_file().is_err());
        assert_eq!(
            service.get_connect_metric_from_file().unwrap().0,
            ConnectMetricConfig::default()
        );
    }

    #[tokio::test]
    async fn password_rotation_repairs_a_mistyped_file_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(landscape_common::LAND_CONFIG);
        std::fs::write(&path, "auth = { admin_user = 'operator', admin_pass = 42 }\n").unwrap();
        let read_runtime = || {
            RuntimeConfig::new(WebCommArgs {
                config_dir: Some(dir.path().to_owned()),
                ..Default::default()
            })
        };
        let runtime = read_runtime();
        let request = ChangePasswordRequest {
            current_password: runtime.auth.admin_pass.clone(),
            new_password: "NewPassword123".into(),
            confirm_password: "NewPassword123".into(),
        };
        let service =
            LandscapeConfigService::new(runtime, LandscapeDBServiceProvider::mem_test_db().await)
                .await;
        service.change_password(request).await.unwrap();
        let restored = read_runtime();
        assert_eq!(restored.auth.admin_pass, service.shared_auth().load().admin_pass);
        assert_eq!(restored.auth.admin_pass, "NewPassword123");
        assert_eq!(restored.auth.admin_user, "operator");
    }

    #[tokio::test]
    async fn invalid_username_preserves_password_at_startup_and_after_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(landscape_common::LAND_CONFIG);
        std::fs::write(&path, "[auth]\nadmin_user = 42\nadmin_pass = 'configured'\n").unwrap();
        let read_runtime = || {
            RuntimeConfig::new(WebCommArgs {
                config_dir: Some(dir.path().to_owned()),
                ..Default::default()
            })
        };
        let service = LandscapeConfigService::new(
            read_runtime(),
            LandscapeDBServiceProvider::mem_test_db().await,
        )
        .await;
        let auth = service.shared_auth();
        assert_eq!(auth.load().admin_pass, "configured");
        service
            .change_password(ChangePasswordRequest {
                current_password: "configured".into(),
                new_password: "AnotherPassword1".into(),
                confirm_password: "AnotherPassword1".into(),
            })
            .await
            .unwrap();
        assert_eq!(auth.load().admin_pass, "AnotherPassword1");
        assert_eq!(read_runtime().auth.admin_pass, "AnotherPassword1");
        let disk: toml::Table = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(disk["auth"]["admin_user"].as_integer(), Some(42));
    }

    #[tokio::test]
    async fn password_from_startup_arguments_cannot_be_overridden_by_api() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = RuntimeConfig::new(WebCommArgs {
            config_dir: Some(dir.path().into()),
            admin_pass: Some("from-startup".into()),
            ..Default::default()
        });
        let service =
            LandscapeConfigService::new(runtime, LandscapeDBServiceProvider::mem_test_db().await)
                .await;
        let result = service
            .change_password(ChangePasswordRequest {
                current_password: "from-startup".into(),
                new_password: "UpdatedPass1".into(),
                confirm_password: "UpdatedPass1".into(),
            })
            .await;
        assert!(matches!(
            result,
            Err(ConfigUpdateError::Password(
                landscape_common::sys_config::auth::api::PasswordChangeError::ManagedExternally
            ))
        ));
        assert!(!service.get_config_path().exists());
        assert_eq!(service.auth.load().admin_pass, "from-startup");
    }

    #[tokio::test]
    async fn export_reports_malformed_gateway_rule_by_id() {
        use landscape_common::sys_service::gateway::GatewayError;
        use landscape_database::repository::Repository;
        use sea_orm::ConnectionTrait;

        let (_dir, service) = service().await;
        let store = service.store.gateway_http_upstream_store();
        let rule = serde_json::from_value(serde_json::json!({
            "name": "export", "enable": true, "domains": ["export.example.com"], "match_rule": { "t": "host" },
            "upstream": { "targets": [{ "address": "127.0.0.1", "port": 8080 }] }
        }))
        .unwrap();
        let id = store.upsert(rule).await.unwrap().new.id;
        assert_eq!(service.export_init_config().await.unwrap().gateway_rules[0].id, id);
        Repository::db(&store)
            .execute_unprepared("UPDATE gateway_http_upstream_rules SET upstream = 'false'")
            .await
            .unwrap();
        assert!(matches!(service.export_init_config().await,
            Err(InitConfigError::Gateway(GatewayError::InvalidStoredRule { id: bad_id, .. })) if bad_id == id));
    }

    #[tokio::test]
    async fn invalid_updates_do_not_change_file_or_memory() {
        let (_dir, service) = service().await;
        let content = "# preserve this file\n";
        std::fs::write(service.get_config_path(), content).unwrap();
        let before = Arc::clone(&service.config.load_full());
        let result = service
            .update_doh_config(
                LandscapeDohConfig { listen_port: Some(53), ..Default::default() },
                LandscapeConfigService::section_hash(&LandscapeDohConfig::default()).unwrap(),
            )
            .await;
        assert!(matches!(result, Err(ConfigUpdateError::Dns(_))));
        let result = service
            .update_connect_metric_config(
                ConnectMetricConfig {
                    store: landscape_common::sys_config::MetricStoreConfig {
                        cleanup_time_budget_secs: Some(61),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                LandscapeConfigService::section_hash(&ConnectMetricConfig::default()).unwrap(),
            )
            .await;
        assert!(matches!(result, Err(ConfigUpdateError::Metric(_))));
        let result = service
            .update_lan_hostname_config(
                LandscapeLanHostnameConfig {
                    lan_suffix: Some("corp.test".into()),
                    ..Default::default()
                },
                LandscapeConfigService::section_hash(&LandscapeLanHostnameConfig::default())
                    .unwrap(),
            )
            .await;
        assert!(matches!(result, Err(ConfigUpdateError::LanHostname(_))));
        assert!(Arc::ptr_eq(&before, &service.config.load_full()));
        assert_eq!(std::fs::read_to_string(service.get_config_path()).unwrap(), content);
    }

    #[tokio::test]
    async fn dns_saves_migrate_only_the_edited_block_and_preserve_external_edits() {
        let (_dir, service) = service().await;
        let path = service.get_config_path();
        let old = "# user comment\n[dns]\ntcp_enabled = false\ncache_ttl = 300\ndoh_listen_port = 8443\nextra = 42\n";
        std::fs::write(&path, old).unwrap();
        let (cache, cache_hash) = service.get_dns_cache_from_file().unwrap();
        let (doh, doh_hash) = service.get_doh_from_file().unwrap();
        let mut cache_rx = service.subscribe_dns_cache();
        let mut doh_rx = service.subscribe_doh();
        assert_eq!(cache.ttl, Some(300));
        assert_eq!(doh.listen_port, Some(8443));

        std::fs::write(&path, old.replace("extra = 42", "extra = 43")).unwrap();
        let new_cache = LandscapeDnsCacheConfig { ttl: Some(12), ..Default::default() };
        service.update_dns_cache_config(new_cache.clone(), cache_hash.clone()).await.unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        for retained in ["# user comment", "extra = 43", "doh_listen_port = 8443", "[dns.cache]"] {
            assert!(saved.contains(retained), "{saved}");
        }
        assert!(!saved.contains("cache_ttl") && !saved.contains("tcp_enabled"));
        assert_eq!(*cache_rx.borrow_and_update(), new_cache.build_runtime());
        assert!(!doh_rx.has_changed().unwrap());
        assert!(matches!(
            service.update_dns_cache_config(Default::default(), cache_hash).await,
            Err(ConfigUpdateError::Storage(DbError::Conflict))
        ));
        assert!(!cache_rx.has_changed().unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), saved);

        let (_, cache_hash) = service.get_dns_cache_from_file().unwrap();
        let (a, b) = tokio::join!(
            service.update_dns_cache_config(Default::default(), cache_hash),
            service.update_doh_config(doh.clone(), doh_hash),
        );
        a.unwrap();
        b.unwrap();
        let saved = std::fs::read_to_string(&path).unwrap();
        let restarted: LandscapeConfig = toml::from_str(&saved).unwrap();
        assert!(saved.contains("[dns.doh]") && !saved.contains("doh_listen_port"));
        assert_eq!(*cache_rx.borrow_and_update(), CacheRuntimeConfig::default());
        assert_eq!(restarted.dns.cache.build_runtime(), *cache_rx.borrow());
        assert_eq!(restarted.dns.doh.build_runtime(), *doh_rx.borrow_and_update());

        // Saving the same desired endpoint must not interrupt the live listener.
        let (_, hash) = service.get_doh_from_file().unwrap();
        service.update_doh_config(doh, hash).await.unwrap();
        assert!(!doh_rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn failed_dns_write_keeps_the_committed_config_and_watch_value() {
        let (dir, service) = service().await;
        let (_, hash) = service.get_doh_from_file().unwrap();
        let rx = service.subscribe_doh();
        let previous = service.config.load_full();
        // Remove the temporary config directory so creation of the transaction file fails.
        dir.close().unwrap();
        let result = service
            .update_doh_config(
                LandscapeDohConfig { listen_port: Some(8443), ..Default::default() },
                hash,
            )
            .await;
        assert!(matches!(result, Err(ConfigUpdateError::Storage(_))));
        assert!(Arc::ptr_eq(&previous, &service.config.load_full()));
        assert!(!rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn metric_clear_matches_restart_and_conflicts_do_not_commit() {
        let (dir, service) = service().await;
        let mut metric = service.subscribe_connect_metric();
        let (_, hash) = service.get_connect_metric_from_file().unwrap();
        service
            .update_connect_metric_config(
                ConnectMetricConfig {
                    write_batch_size: Some(123),
                    retention_1d_days: Some(42),
                    ..Default::default()
                },
                hash.clone(),
            )
            .await
            .unwrap();
        assert_eq!(metric.borrow_and_update().write_batch_size, 123);
        let content = std::fs::read_to_string(service.get_config_path()).unwrap();
        assert!(matches!(
            service.update_connect_metric_config(ConnectMetricConfig::default(), hash).await,
            Err(ConfigUpdateError::Storage(DbError::Conflict))
        ));
        assert!(!metric.has_changed().unwrap());
        assert_eq!(metric.borrow().write_batch_size, 123);
        assert_eq!(std::fs::read_to_string(service.get_config_path()).unwrap(), content);
        let (_, hash) = service.get_connect_metric_from_file().unwrap();
        service.update_connect_metric_config(ConnectMetricConfig::default(), hash).await.unwrap();
        let restarted = RuntimeConfig::new(WebCommArgs {
            config_dir: Some(dir.path().to_path_buf()),
            database_path: Some("sqlite::memory:".into()),
            ..Default::default()
        });
        assert!(metric.has_changed().unwrap());
        assert_eq!(*metric.borrow_and_update(), restarted.metric_connect);
        let (_, hash) = service.get_connect_metric_from_file().unwrap();
        service.update_connect_metric_config(ConnectMetricConfig::default(), hash).await.unwrap();
        assert!(!metric.has_changed().unwrap());
        assert_eq!(
            restarted.metric_connect,
            (ConnectMetricConfig::default()).to_runtime().unwrap()
        );
    }
    #[tokio::test]
    async fn editing_legacy_sections_preserves_sibling_values_and_hashes() {
        let (_dir, service) = service().await;
        std::fs::write(
            service.get_config_path(),
            "[metric]\nmode='memory'\ncleanup_interval_secs=42\n[metric.dns]\n# keep DNS comment\nfuture_option=true\n[time]\ntimezone='UTC'\n",
        )
        .unwrap();
        let dns = service.subscribe_dns_metric();
        let monitor = service.subscribe_self_monitor();
        let (old_dns, dns_hash) = service.get_dns_metric_from_file().unwrap();
        let (old_monitor, monitor_hash) = service.get_self_monitor_from_file().unwrap();
        let (_, hash) = service.get_connect_metric_from_file().unwrap();
        service.update_connect_metric_config(ConnectMetricConfig::default(), hash).await.unwrap();
        assert_eq!(
            service.get_connect_metric_from_file().unwrap().0,
            ConnectMetricConfig::default()
        );
        assert_eq!(service.get_dns_metric_from_file().unwrap(), (old_dns.clone(), dns_hash));
        let saved = std::fs::read_to_string(service.get_config_path()).unwrap();
        assert!(saved.contains("# keep DNS comment"));
        assert!(saved.contains("future_option=true"));
        assert_eq!(old_dns.store.cleanup_interval_secs, Some(42));
        assert_eq!(old_monitor.history_enabled, Some(false));
        assert_eq!(service.get_self_monitor_from_file().unwrap(), (old_monitor, monitor_hash));
        assert!(!dns.has_changed().unwrap());
        assert!(!monitor.has_changed().unwrap());
    }

    #[tokio::test]
    async fn time_update_uses_the_same_normalized_runtime_as_restart() {
        let (dir, service) = service().await;
        let (_, hash) = service.get_time_config_from_file().unwrap();
        let mut published = None;
        service
            .update_time_config(
                LandscapeTimeConfig {
                    sync_interval_secs: Some(0),
                    timeout_secs: Some(0),
                    samples_per_server: Some(0),
                    ..Default::default()
                },
                hash,
                |runtime| {
                    assert!(service.write_lock.try_lock().is_err());
                    let saved: LandscapeConfig = toml::from_str(
                        &std::fs::read_to_string(service.get_config_path()).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(runtime, saved.time.to_runtime().unwrap());
                    published = Some(runtime);
                },
            )
            .await
            .unwrap();
        let runtime = service.get_time_runtime_config();
        assert_eq!(published, Some(runtime.clone()));
        assert_eq!(runtime.sync_interval_secs, 1);
        assert_eq!(runtime.timeout_secs, 1);
        assert_eq!(runtime.samples_per_server, 1);
        let restarted = RuntimeConfig::new(WebCommArgs {
            config_dir: Some(dir.path().to_path_buf()),
            database_path: Some("sqlite::memory:".into()),
            ..Default::default()
        });
        assert_eq!(runtime, restarted.time);
    }
    #[tokio::test]
    async fn lan_save_keeps_canonical_suffix_and_blank_restores_default() {
        let (_dir, service) = service().await;
        for (input, saved, effective) in [
            (" .Home.ARPA. ", Some("home.arpa"), "home.arpa"),
            ("   ", None, landscape_common::DEFAULT_DNS_LAN_SUFFIX),
        ] {
            let (_, hash) = service.get_lan_hostname_config_from_file().unwrap();
            service
                .update_lan_hostname_config(
                    LandscapeLanHostnameConfig {
                        enable: Some(true),
                        lan_suffix: Some(input.into()),
                    },
                    hash,
                )
                .await
                .unwrap();
            let (file, _) = service.get_lan_hostname_config_from_file().unwrap();
            assert_eq!(file.lan_suffix.as_deref(), saved);
            assert_eq!(service.get_lan_hostname_config_from_memory().lan_suffix.as_deref(), saved);
            let runtime = service.get_lan_hostname_runtime_config();
            assert!(runtime.enable);
            assert_eq!(runtime.lan_suffix, effective);
            assert_eq!(service.shared_lan_hostname().load().as_ref(), &runtime);
        }
    }
    #[tokio::test]
    async fn a_rejected_time_edit_never_publishes_or_changes_runtime() {
        let (dir, service) = service().await;
        let (_, hash) = service.get_time_config_from_file().unwrap();
        let previous = service.get_time_runtime_config();
        let invalid_servers = LandscapeTimeConfig {
            enabled: Some(true),
            servers: Some(vec!["ntp..example".into()]),
            ..Default::default()
        };
        let rejected = service
            .update_time_config(invalid_servers, hash.clone(), |_| {
                panic!("published invalid NTP server")
            })
            .await;
        assert!(matches!(
            rejected,
            Err(ConfigUpdateError::Time(
                landscape_common::sys_service::time_sync::TimeSyncError::InvalidServers
            ))
        ));
        assert_eq!(service.get_time_runtime_config(), previous);
        assert_eq!(service.get_time_config_from_file().unwrap().1, hash);

        let update = LandscapeTimeConfig {
            enabled: Some(!previous.enabled),
            ..Default::default()
        };
        let rejected = service
            .update_time_config(update.clone(), "stale".into(), |_| {
                panic!("published conflicting edit")
            })
            .await;
        assert!(matches!(rejected, Err(ConfigUpdateError::Storage(DbError::Conflict))));
        assert_eq!(service.get_time_config_from_file().unwrap().1, hash);
        // Even a current hash cannot commit if the temporary file cannot be created.
        dir.close().unwrap();
        assert!(
            service
                .update_time_config(update, hash, |_| panic!("published failed write"))
                .await
                .is_err()
        );
        assert_eq!(service.get_time_runtime_config(), previous);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_password_changes_only_accept_the_old_password_once() {
        use landscape_common::sys_config::auth::api::PasswordChangeError;
        let (_dir, service) = service().await;
        let shared = service.shared_auth();
        let previous = shared.load().admin_pass.clone();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let change = |password: &'static str| {
            let service = service.clone();
            let barrier = barrier.clone();
            let current_password = previous.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                let result = service
                    .change_password(ChangePasswordRequest {
                        current_password,
                        new_password: password.into(),
                        confirm_password: password.into(),
                    })
                    .await;
                (password, result)
            })
        };
        let (first, second) = tokio::join!(change("PasswordOne1"), change("PasswordTwo2"));
        let mut accepted = Vec::new();
        for (password, result) in [first.unwrap(), second.unwrap()] {
            match result {
                Ok(()) => accepted.push(password),
                Err(ConfigUpdateError::Password(PasswordChangeError::CurrentPasswordIncorrect)) => {
                }
                Err(error) => panic!("unexpected password change error: {error}"),
            }
        }
        assert_eq!(accepted.len(), 1);
        let file: LandscapeConfig =
            toml::from_str(&std::fs::read_to_string(service.get_config_path()).unwrap()).unwrap();
        assert_eq!(file.auth.admin_pass.as_deref(), Some(accepted[0]));
        assert_eq!(shared.load().admin_pass, accepted[0]);
    }
}
