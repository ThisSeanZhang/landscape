use arc_swap::ArcSwap;
use fs2::FileExt;
use landscape_common::config::{
    InitConfig, LandscapeConfig, LandscapeDnsConfig, LandscapeMetricConfig, LandscapeTimeConfig,
    LandscapeUIConfig, RuntimeConfig,
};
use landscape_common::database::LandscapeStore;
use landscape_common::error::{LdError, LdResult};
use landscape_common::gateway::settings::{GatewayRuntimeConfig, LandscapeGatewayConfig};
use landscape_database::provider::LandscapeDBServiceProvider;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::sync::Arc;
use toml_edit::DocumentMut;

#[derive(Clone)]
pub struct LandscapeConfigService {
    config: Arc<ArcSwap<RuntimeConfig>>,
    store: LandscapeDBServiceProvider,
}

impl LandscapeConfigService {
    pub async fn new(config: RuntimeConfig, store: LandscapeDBServiceProvider) -> Self {
        LandscapeConfigService {
            config: Arc::new(ArcSwap::from_pointee(config)),
            store,
        }
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
            icmpras: self.store.ra_service_store().list().await.unwrap(),
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
            static_nat_mappings: self.store.static_nat_mapping_store().list().await.unwrap(),
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

        let mut hasher = Sha256::new();
        hasher.update(toml::to_string(&config.file_config).unwrap().as_bytes());
        let hash = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

        (dns, hash)
    }

    pub fn get_dns_runtime_config(&self) -> landscape_common::config::DnsRuntimeConfig {
        self.config.load().dns.clone()
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
        let (config, hash) = self.get_config_with_hash().await.unwrap_or_default();
        (config.time, hash)
    }

    pub async fn get_dns_config_from_file(&self) -> (LandscapeDnsConfig, String) {
        let (config, hash) = self.get_config_with_hash().await.unwrap_or_default();
        (config.dns, hash)
    }

    pub async fn get_gateway_config_from_file(&self) -> (LandscapeGatewayConfig, String) {
        let (config, hash) = self.get_config_with_hash().await.unwrap_or_default();
        (config.gateway, hash)
    }

    pub fn get_config_path(&self) -> std::path::PathBuf {
        self.config.load().home_path.join(landscape_common::LAND_CONFIG)
    }

    pub async fn get_config_with_hash(&self) -> LdResult<(LandscapeConfig, String)> {
        let path = self.get_config_path();

        let content = if path.exists() { std::fs::read_to_string(&path)? } else { String::new() };

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

        let config: LandscapeConfig = if content.is_empty() {
            LandscapeConfig::default()
        } else {
            toml::from_str(&content).map_err(|e| LdError::ConfigError(e.to_string()))?
        };

        Ok((config, hash))
    }

    pub async fn update_ui_config(
        &self,
        new_ui: LandscapeUIConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        let path = self.get_config_path();

        let file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;

        file.lock_exclusive()?;

        let result = {
            let mut content = String::new();
            let mut file_obj = &file;
            file_obj.read_to_string(&mut content)?;

            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let current_hash =
                hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

            if current_hash != expected_hash {
                return Err(LdError::ConfigConflict);
            }

            let mut doc =
                content.parse::<DocumentMut>().map_err(|e| LdError::ConfigError(e.to_string()))?;

            let ui_value =
                toml::to_string(&new_ui).map_err(|e| LdError::ConfigError(e.to_string()))?;
            let ui_doc =
                ui_value.parse::<DocumentMut>().map_err(|e| LdError::ConfigError(e.to_string()))?;

            doc["ui"] = ui_doc.as_item().clone();

            let new_content = doc.to_string();

            let tmp_path = path.with_extension("toml.tmp");
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp_file = opts.open(&tmp_path)?;

            tmp_file.write_all(new_content.as_bytes())?;
            tmp_file.sync_all()?;

            std::fs::rename(&tmp_path, &path)?;

            Ok::<(), LdError>(())
        };

        file.unlock()?;

        if let Err(e) = result {
            return Err(e);
        }

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.ui = new_ui.clone();
            new_config.file_config.ui = new_ui.clone();
            new_config
        });

        Ok(())
    }
    pub async fn update_metric_config(
        &self,
        new_metric: LandscapeMetricConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        let path = self.get_config_path();

        let file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;

        file.lock_exclusive()?;

        let result = {
            let mut content = String::new();
            let mut file_obj = &file;
            file_obj.read_to_string(&mut content)?;

            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let current_hash =
                hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

            if current_hash != expected_hash {
                return Err(LdError::ConfigConflict);
            }

            let mut doc =
                content.parse::<DocumentMut>().map_err(|e| LdError::ConfigError(e.to_string()))?;

            let metric_value =
                toml::to_string(&new_metric).map_err(|e| LdError::ConfigError(e.to_string()))?;
            let metric_doc = metric_value
                .parse::<DocumentMut>()
                .map_err(|e| LdError::ConfigError(e.to_string()))?;

            doc["metric"] = metric_doc.as_item().clone();

            let new_content = doc.to_string();

            let tmp_path = path.with_extension("toml.tmp");
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp_file = opts.open(&tmp_path)?;

            tmp_file.write_all(new_content.as_bytes())?;
            tmp_file.sync_all()?;

            std::fs::rename(&tmp_path, &path)?;

            Ok::<(), LdError>(())
        };

        file.unlock()?;

        if let Err(e) = result {
            return Err(e);
        }

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.metric.update_from_file_config(&new_metric);
            new_config.file_config.metric = new_metric.clone();
            new_config
        });

        Ok(())
    }

    pub async fn update_dns_config(
        &self,
        new_dns: LandscapeDnsConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        let path = self.get_config_path();

        let file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;

        file.lock_exclusive()?;

        let result = {
            let mut content = String::new();
            let mut file_obj = &file;
            file_obj.read_to_string(&mut content)?;

            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let current_hash =
                hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

            if current_hash != expected_hash {
                return Err(LdError::ConfigConflict);
            }

            let mut doc =
                content.parse::<DocumentMut>().map_err(|e| LdError::ConfigError(e.to_string()))?;

            let dns_value =
                toml::to_string(&new_dns).map_err(|e| LdError::ConfigError(e.to_string()))?;
            let dns_doc = dns_value
                .parse::<DocumentMut>()
                .map_err(|e| LdError::ConfigError(e.to_string()))?;

            doc["dns"] = dns_doc.as_item().clone();

            let new_content = doc.to_string();

            let tmp_path = path.with_extension("toml.tmp");
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp_file = opts.open(&tmp_path)?;

            tmp_file.write_all(new_content.as_bytes())?;
            tmp_file.sync_all()?;

            std::fs::rename(&tmp_path, &path)?;

            Ok::<(), LdError>(())
        };

        file.unlock()?;

        if let Err(e) = result {
            return Err(e);
        }

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.dns.update_from_file_config(&new_dns);
            new_config.file_config.dns = new_dns.clone();
            new_config
        });

        Ok(())
    }

    pub async fn update_time_config(
        &self,
        new_time: LandscapeTimeConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        let path = self.get_config_path();

        let file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;

        file.lock_exclusive()?;

        let result = {
            let mut content = String::new();
            let mut file_obj = &file;
            file_obj.read_to_string(&mut content)?;

            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let current_hash =
                hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

            if current_hash != expected_hash {
                return Err(LdError::ConfigConflict);
            }

            let mut doc =
                content.parse::<DocumentMut>().map_err(|e| LdError::ConfigError(e.to_string()))?;

            let time_value =
                toml::to_string(&new_time).map_err(|e| LdError::ConfigError(e.to_string()))?;
            let time_doc = time_value
                .parse::<DocumentMut>()
                .map_err(|e| LdError::ConfigError(e.to_string()))?;

            doc["time"] = time_doc.as_item().clone();

            let new_content = doc.to_string();

            let tmp_path = path.with_extension("toml.tmp");
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp_file = opts.open(&tmp_path)?;

            tmp_file.write_all(new_content.as_bytes())?;
            tmp_file.sync_all()?;

            std::fs::rename(&tmp_path, &path)?;

            Ok::<(), LdError>(())
        };

        file.unlock()?;

        if let Err(e) = result {
            return Err(e);
        }

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.time.update_from_file_config(&new_time);
            new_config.file_config.time = new_time.clone();
            new_config
        });
        landscape_common::utils::time::update_time_sync_config(self.config.load().time.clone());

        Ok(())
    }

    pub async fn update_gateway_config(
        &self,
        new_gateway: LandscapeGatewayConfig,
        expected_hash: String,
    ) -> LdResult<()> {
        let path = self.get_config_path();

        let file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;

        file.lock_exclusive()?;

        let result = {
            let mut content = String::new();
            let mut file_obj = &file;
            file_obj.read_to_string(&mut content)?;

            let mut hasher = Sha256::new();
            hasher.update(content.as_bytes());
            let current_hash =
                hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect::<String>();

            if current_hash != expected_hash {
                return Err(LdError::ConfigConflict);
            }

            let mut doc =
                content.parse::<DocumentMut>().map_err(|e| LdError::ConfigError(e.to_string()))?;

            let gateway_value =
                toml::to_string(&new_gateway).map_err(|e| LdError::ConfigError(e.to_string()))?;
            let gateway_doc = gateway_value
                .parse::<DocumentMut>()
                .map_err(|e| LdError::ConfigError(e.to_string()))?;

            doc["gateway"] = gateway_doc.as_item().clone();

            let new_content = doc.to_string();

            let tmp_path = path.with_extension("toml.tmp");
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp_file = opts.open(&tmp_path)?;

            tmp_file.write_all(new_content.as_bytes())?;
            tmp_file.sync_all()?;

            std::fs::rename(&tmp_path, &path)?;

            Ok::<(), LdError>(())
        };

        file.unlock()?;

        if let Err(e) = result {
            return Err(e);
        }

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.gateway = GatewayRuntimeConfig::from_file_config(&new_gateway);
            new_config.file_config.gateway = new_gateway.clone();
            new_config
        });

        Ok(())
    }

    pub fn update_auth_password(&self, new_password: String) -> LdResult<()> {
        let path = self.get_config_path();

        let file = OpenOptions::new().read(true).write(true).create(true).open(&path)?;

        file.lock_exclusive()?;

        let result = (|| {
            let mut content = String::new();
            (&file).read_to_string(&mut content)?;

            let mut doc =
                content.parse::<DocumentMut>().map_err(|e| LdError::ConfigError(e.to_string()))?;

            doc["auth"]["admin_pass"] = toml_edit::value(&new_password);

            let new_content = doc.to_string();

            let tmp_path = path.with_extension("toml.tmp");
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut tmp_file = opts.open(&tmp_path)?;

            tmp_file.write_all(new_content.as_bytes())?;
            tmp_file.sync_all()?;

            std::fs::rename(&tmp_path, &path)?;

            Ok::<(), LdError>(())
        })();

        if file.unlock().is_err() {
            tracing::warn!("Failed to release file lock on {}", path.display());
        }

        result?;

        self.config.rcu(|old| {
            let mut new_config = (**old).clone();
            new_config.auth.admin_pass = new_password.clone();
            new_config.file_config.auth.admin_pass = Some(new_password.clone());
            new_config
        });

        Ok(())
    }
}
