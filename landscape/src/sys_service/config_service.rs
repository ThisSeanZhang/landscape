use arc_swap::ArcSwap;
use fs2::FileExt;
use landscape_common::config::{
    InitConfig, LandscapeConfig, LandscapeDnsConfig, LandscapeMetricConfig, LandscapeUIConfig,
    RuntimeConfig,
};
use landscape_common::database::LandscapeDBTrait;
use landscape_common::error::{LdError, LdResult};
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
            ip_mac_bindings: self.store.ip_mac_binding_store().list().await.unwrap(),
        }
    }

    pub fn get_ui_config_from_memory(&self) -> LandscapeUIConfig {
        self.config.load().ui.clone()
    }

    pub fn get_metric_config_from_memory(&self) -> LandscapeMetricConfig {
        self.config.load().file_config.metric.clone()
    }

    pub fn get_dns_config(&self) -> (LandscapeDnsConfig, String) {
        let config = self.config.load();
        let dns = config.file_config.dns.clone();

        let mut hasher = Sha256::new();
        hasher.update(toml::to_string(&config.file_config).unwrap().as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        (dns, hash)
    }

    pub async fn get_dns_config_from_file(&self) -> (LandscapeDnsConfig, String) {
        let (config, hash) = self.get_config_with_hash().await.unwrap_or_default();
        (config.dns, hash)
    }

    pub fn get_config_path(&self) -> std::path::PathBuf {
        self.config.load().home_path.join(landscape_common::LAND_CONFIG)
    }

    pub async fn get_config_with_hash(&self) -> LdResult<(LandscapeConfig, String)> {
        let path = self.get_config_path();

        let content = if path.exists() { std::fs::read_to_string(&path)? } else { String::new() };

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

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
            let current_hash = format!("{:x}", hasher.finalize());

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
            let mut tmp_file =
                OpenOptions::new().write(true).create(true).truncate(true).open(&tmp_path)?;

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
            let current_hash = format!("{:x}", hasher.finalize());

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
            let mut tmp_file =
                OpenOptions::new().write(true).create(true).truncate(true).open(&tmp_path)?;

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
            let current_hash = format!("{:x}", hasher.finalize());

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
            let mut tmp_file =
                OpenOptions::new().write(true).create(true).truncate(true).open(&tmp_path)?;

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
}
