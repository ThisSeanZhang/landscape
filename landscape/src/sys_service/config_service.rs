use arc_swap::ArcSwap;
use landscape_common::config::{
    InitConfig, LandscapeConfig, LandscapeDnsConfig, LandscapeLanHostnameConfig,
    LandscapeMetricConfig, LandscapeTimeConfig, LandscapeUIConfig, RuntimeConfig,
};
use landscape_common::database::LandscapeStore;
use landscape_common::error::{LdError, LdResult};
use landscape_common::sys_service::gateway::settings::{
    GatewayRuntimeConfig, LandscapeGatewayConfig,
};
use landscape_common::sys_service::lan_hostname::LanHostnameConfig;
use landscape_core::time::update_time_sync_config;
use landscape_database::provider::LandscapeDBServiceProvider;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use toml_edit::DocumentMut;
use uuid::Uuid;

#[derive(Clone)]
pub struct LandscapeConfigService {
    config: Arc<ArcSwap<RuntimeConfig>>,
    store: LandscapeDBServiceProvider,
    write_lock: Arc<Mutex<()>>,
}

impl LandscapeConfigService {
    pub async fn new(config: RuntimeConfig, store: LandscapeDBServiceProvider) -> Self {
        LandscapeConfigService {
            config: Arc::new(ArcSwap::from_pointee(config)),
            store,
            write_lock: Arc::new(Mutex::new(())),
        }
    }

    fn section_hash<T: Serialize>(config: &T) -> LdResult<String> {
        let content =
            toml::to_string(config).map_err(|error| LdError::ConfigError(error.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        Ok(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
    }

    fn read_config_file(path: &Path) -> LdResult<(String, LandscapeConfig)> {
        let content = if path.exists() { std::fs::read_to_string(path)? } else { String::new() };
        let config = if content.is_empty() {
            LandscapeConfig::default()
        } else {
            toml::from_str(&content).map_err(|error| LdError::ConfigError(error.to_string()))?
        };
        Ok((content, config))
    }

    fn parse_document(content: &str) -> LdResult<DocumentMut> {
        content
            .parse()
            .map_err(|error: toml_edit::TomlError| LdError::ConfigError(error.to_string()))
    }

    fn set_section<T: Serialize>(
        document: &mut DocumentMut,
        name: &str,
        config: &T,
    ) -> LdResult<()> {
        let content =
            toml::to_string(config).map_err(|error| LdError::ConfigError(error.to_string()))?;
        let section = Self::parse_document(&content)?;
        document[name] = section.as_item().clone();
        Ok(())
    }

    fn write_config_file(path: &Path, content: &str) -> LdResult<()> {
        let file_name = path.file_name().and_then(|name| name.to_str()).unwrap_or("landscape.toml");
        let tmp_path = path.with_file_name(format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            Uuid::new_v4()
        ));

        let result = (|| -> LdResult<()> {
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
            Ok(())
        })();

        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        result
    }

    fn ensure_expected_hash<T: Serialize>(config: &T, expected_hash: &str) -> LdResult<()> {
        if Self::section_hash(config)? != expected_hash {
            return Err(LdError::ConfigConflict);
        }
        Ok(())
    }

    fn read_section_from_file<T, Select>(&self, select: Select) -> LdResult<(T, String)>
    where
        T: Serialize,
        Select: FnOnce(LandscapeConfig) -> T,
    {
        let (_, config) = Self::read_config_file(&self.get_config_path())?;
        let section = select(config);
        let hash = Self::section_hash(&section)?;
        Ok((section, hash))
    }

    async fn update_section<T, Select, Commit>(
        &self,
        section_name: &str,
        aliases: &[&str],
        new_config: T,
        expected_hash: String,
        select: Select,
        commit: Commit,
    ) -> LdResult<()>
    where
        T: Serialize,
        Select: for<'a> Fn(&'a LandscapeConfig) -> &'a T,
        Commit: FnOnce(&T),
    {
        let _guard = self.write_lock.lock().await;
        let path = self.get_config_path();
        let (content, current_config) = Self::read_config_file(&path)?;
        Self::ensure_expected_hash(select(&current_config), &expected_hash)?;

        let mut document = Self::parse_document(&content)?;
        for alias in aliases {
            document.remove(alias);
        }
        Self::set_section(&mut document, section_name, &new_config)?;
        Self::write_config_file(&path, &document.to_string())?;
        commit(&new_config);

        Ok(())
    }

    pub async fn export_init_config(&self) -> InitConfig {
        let config = self.config.load();
        InitConfig {
            version: landscape_common::VERSION.to_string(),
            config: config.file_config.clone(),
            ifaces: self.store.iface_store().list().await.unwrap(),
            ipconfigs: self.store.iface_ip_service_store().list().await.unwrap(),
            nats: self.store.nat_service_store().list().await.unwrap(),
            marks: self.store.flow_wan_service_store().list().await.unwrap(),
            pppds: self.store.pppd_service_store().list().await.unwrap(),
            flow_rules: self.store.flow_rule_store().list().await.unwrap(),
            dns_rules: self.store.dns_rule_store().list().await.unwrap(),
            dst_ip_mark: self.store.dst_ip_rule_store().list().await.unwrap(),
            dhcpv6pds: self.store.dhcp_v6_client_store().list().await.unwrap(),
            firewalls: self.store.firewall_service_store().list().await.unwrap(),
            firewall_rules: self.store.firewall_rule_store().list().await.unwrap(),
            firewall_blacklists: self.store.firewall_blacklist_store().list().await.unwrap(),
            wifi_configs: self.store.wifi_service_store().list().await.unwrap(),
            dhcpv4_services: self.store.dhcp_v4_server_store().list().await.unwrap(),
            mss_clamps: self.store.mss_clamp_service_store().list().await.unwrap(),
            geo_ips: self.store.geo_ip_rule_store().list().await.unwrap(),
            geo_sites: self.store.geo_site_rule_store().list().await.unwrap(),
            route_lans: self.store.route_lan_service_store().list().await.unwrap(),
            route_wans: self.store.route_wan_service_store().list().await.unwrap(),
            static_nat_mappings_v4: self.store.static_nat_mapping_v4_store().list().await.unwrap(),
            static_nat_mappings_v6: self.store.static_nat_mapping_v6_store().list().await.unwrap(),
            dns_redirects: self.store.dns_redirect_rule_store().list().await.unwrap(),
            dns_upstream_configs: self.store.dns_upstream_config_store().list().await.unwrap(),
            enrolled_devices: self.store.enrolled_device_store().list().await.unwrap(),
            lan_ipv6s: self.store.lan_ipv6_v2_service_store().list().await.unwrap(),
            cert_accounts: self.store.cert_account_store().list().await.unwrap(),
            certs: self.store.cert_store().list().await.unwrap(),
            gateway_rules: self.store.gateway_http_upstream_store().list().await.unwrap(),
            ddns_jobs: self.store.ddns_job_store().list().await.unwrap(),
            dns_provider_profiles: self.store.dns_provider_profile_store().list().await.unwrap(),
        }
    }

    pub fn get_ui_config_from_memory(&self) -> LandscapeUIConfig {
        self.config.load().ui.clone()
    }

    pub fn get_auth_config(&self) -> landscape_common::config::AuthRuntimeConfig {
        self.config.load().auth.clone()
    }

    pub fn get_metric_config_from_memory(&self) -> LandscapeMetricConfig {
        self.config.load().file_config.metric.clone()
    }

    pub fn get_metric_runtime_config(&self) -> landscape_common::config::MetricRuntimeConfig {
        self.config.load().metric.clone()
    }

    pub fn get_dns_config(&self) -> (LandscapeDnsConfig, String) {
        let config = self.config.load();
        let dns = config.file_config.dns.clone();
        let hash = Self::section_hash(&dns).unwrap_or_default();
        (dns, hash)
    }

    pub fn get_dns_runtime_config(&self) -> landscape_common::config::DnsRuntimeConfig {
        self.config.load().dns.clone()
    }

    pub fn get_lan_hostname_config_from_memory(&self) -> LandscapeLanHostnameConfig {
        self.config.load().file_config.lan_hostname.clone()
    }

    pub fn get_lan_hostname_runtime_config(&self) -> LanHostnameConfig {
        self.config.load().lan_hostname.clone()
    }

    pub fn get_time_config_from_memory(&self) -> LandscapeTimeConfig {
        self.config.load().file_config.time.clone()
    }

    pub fn get_gateway_config_from_memory(&self) -> LandscapeGatewayConfig {
        self.config.load().file_config.gateway.clone()
    }

    pub fn get_gateway_runtime_config(&self) -> GatewayRuntimeConfig {
        self.config.load().gateway.clone()
    }

    pub async fn get_time_config_from_file(&self) -> (LandscapeTimeConfig, String) {
        self.read_section_from_file(|config| config.time).unwrap_or_default()
    }

    pub async fn get_dns_config_from_file(&self) -> (LandscapeDnsConfig, String) {
        self.read_section_from_file(|config| config.dns).unwrap_or_default()
    }

    pub async fn get_lan_hostname_config_from_file(&self) -> (LandscapeLanHostnameConfig, String) {
        self.read_section_from_file(|config| config.lan_hostname).unwrap_or_default()
    }

    pub async fn get_gateway_config_from_file(&self) -> (LandscapeGatewayConfig, String) {
        self.read_section_from_file(|config| config.gateway).unwrap_or_default()
    }

    pub async fn get_ui_config_from_file(&self) -> LdResult<(LandscapeUIConfig, String)> {
        self.read_section_from_file(|config| config.ui)
    }

    pub async fn get_metric_config_from_file(&self) -> LdResult<(LandscapeMetricConfig, String)> {
        self.read_section_from_file(|config| config.metric)
    }

    pub fn get_config_path(&self) -> std::path::PathBuf {
        self.config.load().home_path.join(landscape_common::LAND_CONFIG)
    }

    pub async fn update_ui_config(
        &self,
        new_ui: LandscapeUIConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        self.update_section(
            "ui",
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
    pub async fn update_metric_config(
        &self,
        new_metric: LandscapeMetricConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        self.update_section(
            "metric",
            &[],
            new_metric,
            expected_hash,
            |config| &config.metric,
            |new_metric| {
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.metric.update_from_file_config(new_metric);
                    new_config.file_config.metric = new_metric.clone();
                    new_config
                });
            },
        )
        .await
    }

    pub async fn update_dns_config(
        &self,
        new_dns: LandscapeDnsConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        self.update_section(
            "dns",
            &[],
            new_dns,
            expected_hash,
            |config| &config.dns,
            |new_dns| {
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.dns.update_from_file_config(new_dns);
                    new_config.file_config.dns = new_dns.clone();
                    new_config
                });
            },
        )
        .await
    }

    pub async fn update_lan_hostname_config(
        &self,
        new_lan_hostname: LandscapeLanHostnameConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        let new_lan_hostname = new_lan_hostname
            .normalized()
            .map_err(|error| LdError::ConfigError(error.to_string()))?;
        self.update_section(
            "lan_hostname",
            &["hostname_registry"],
            new_lan_hostname,
            expected_hash,
            |config| &config.lan_hostname,
            |new_lan_hostname| {
                let runtime = LanHostnameConfig::from_file_config(new_lan_hostname)
                    .expect("normalized LAN hostname config must be valid");
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.lan_hostname = runtime.clone();
                    new_config.file_config.lan_hostname = new_lan_hostname.clone();
                    new_config
                });
            },
        )
        .await
    }

    pub async fn update_time_config(
        &self,
        new_time: LandscapeTimeConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        self.update_section(
            "time",
            &[],
            new_time,
            expected_hash,
            |config| &config.time,
            |new_time| {
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.time.update_from_file_config(new_time);
                    new_config.file_config.time = new_time.clone();
                    new_config
                });
                update_time_sync_config(self.config.load().time.clone());
            },
        )
        .await
    }

    pub async fn update_gateway_config(
        &self,
        new_gateway: LandscapeGatewayConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        self.update_section(
            "gateway",
            &[],
            new_gateway,
            expected_hash,
            |config| &config.gateway,
            |new_gateway| {
                self.config.rcu(|old| {
                    let mut new_config = (**old).clone();
                    new_config.gateway = GatewayRuntimeConfig::from_file_config(new_gateway);
                    new_config.file_config.gateway = new_gateway.clone();
                    new_config
                });
            },
        )
        .await
    }

    pub async fn update_auth_password(&self, new_password: String) -> LdResult<()> {
        let _guard = self.write_lock.lock().await;
        let path = self.get_config_path();
        let (content, _) = Self::read_config_file(&path)?;
        let mut document = Self::parse_document(&content)?;
        document["auth"]["admin_pass"] = toml_edit::value(&new_password);
        Self::write_config_file(&path, &document.to_string())?;

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.auth.admin_pass = new_password.clone();
            new_config.file_config.auth.admin_pass = Some(new_password.clone());
            new_config
        });

        Ok(())
    }
}
