use axum::extract::FromRef;
use landscape::sys_service::config_service::LandscapeConfigService;
use landscape_common::sys_config::{
    ChangePasswordRequest, ConfigUpdateError, UpdateConnectMetricConfigRequest,
    UpdateDnsCacheConfigRequest, UpdateDnsMetricConfigRequest, UpdateDohConfigRequest,
    UpdateGatewayConfigRequest, UpdateLanHostnameConfigRequest, UpdateSelfMonitorConfigRequest,
    UpdateTimeConfigRequest, UpdateUiConfigRequest,
};
use landscape_core::time::SyncTimeService;

use super::LandscapeApp;

pub(crate) enum SystemConfigChange {
    Time(UpdateTimeConfigRequest),
    LanHostname(UpdateLanHostnameConfigRequest),
    DnsCache(UpdateDnsCacheConfigRequest),
    Doh(UpdateDohConfigRequest),
    ConnectMetric(UpdateConnectMetricConfigRequest),
    DnsMetric(UpdateDnsMetricConfigRequest),
    SelfMonitor(UpdateSelfMonitorConfigRequest),
    Gateway(UpdateGatewayConfigRequest),
    Ui(UpdateUiConfigRequest),
    Password(ChangePasswordRequest),
}

#[derive(Clone)]
pub(crate) struct SystemConfigEditor {
    config: LandscapeConfigService,
    pub(super) time: SyncTimeService,
}

impl FromRef<LandscapeApp> for SystemConfigEditor {
    fn from_ref(app: &LandscapeApp) -> Self {
        app.system.settings.clone()
    }
}

impl FromRef<SystemConfigEditor> for LandscapeConfigService {
    fn from_ref(editor: &SystemConfigEditor) -> Self {
        editor.config.clone()
    }
}

impl SystemConfigEditor {
    pub(crate) fn new(config: LandscapeConfigService, time: SyncTimeService) -> Self {
        Self { config, time }
    }

    pub(crate) async fn apply(&self, change: SystemConfigChange) -> Result<(), ConfigUpdateError> {
        use SystemConfigChange::*;
        match change {
            Time(req) => {
                self.config
                    .update_time_config(req.new_time, req.expected_hash, |runtime| {
                        self.time.update_config(runtime)
                    })
                    .await
            }
            LanHostname(req) => {
                self.config
                    .update_lan_hostname_config(req.new_lan_hostname, req.expected_hash)
                    .await
            }
            DnsCache(req) => {
                self.config.update_dns_cache_config(req.new_cache, req.expected_hash).await
            }
            Doh(req) => self.config.update_doh_config(req.new_doh, req.expected_hash).await,
            ConnectMetric(req) => {
                self.config.update_connect_metric_config(req.config, req.expected_hash).await
            }
            DnsMetric(req) => {
                self.config.update_dns_metric_config(req.config, req.expected_hash).await
            }
            SelfMonitor(req) => {
                self.config.update_self_monitor_config(req.config, req.expected_hash).await
            }
            Gateway(req) => {
                Ok(self.config.update_gateway_config(req.new_gateway, req.expected_hash).await?)
            }
            Ui(req) => Ok(self.config.update_ui_config(req.new_ui, req.expected_hash).await?),
            Password(req) => self.config.change_password(req).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::{
        args::WebCommArgs,
        database::error::DbError,
        sys_config::{LandscapeTimeConfig, RuntimeConfig},
    };
    use landscape_database::provider::LandscapeDBServiceProvider;

    #[tokio::test]
    async fn only_committed_time_edits_reach_the_running_service() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(landscape_common::LAND_CONFIG),
            "[time]\nenabled = false\nservers = []\n",
        )
        .unwrap();
        let runtime = RuntimeConfig::new(WebCommArgs {
            config_dir: Some(dir.path().into()),
            ..Default::default()
        });
        let time = SyncTimeService::start(runtime.time.clone());
        let config =
            LandscapeConfigService::new(runtime, LandscapeDBServiceProvider::mem_test_db().await)
                .await;
        let editor = SystemConfigEditor::new(config.clone(), time.clone());
        let (_, hash) = config.get_time_config_from_file().unwrap();
        let edit = |enabled: bool, hash: String| {
            SystemConfigChange::Time(UpdateTimeConfigRequest {
                new_time: LandscapeTimeConfig {
                    enabled: Some(enabled),
                    servers: Some(vec![]),
                    ..Default::default()
                },
                expected_hash: hash,
            })
        };
        assert!(time.sync_now().is_err());
        editor.apply(edit(true, hash.clone())).await.unwrap();
        assert!(time.status().enabled);
        assert!(time.sync_now().is_ok());
        assert!(matches!(
            editor.apply(edit(false, hash)).await,
            Err(ConfigUpdateError::Storage(DbError::Conflict))
        ));
        assert!(time.status().enabled);
        let (saved, hash) = config.get_time_config_from_file().unwrap();
        assert_eq!(saved.enabled, Some(true));
        editor.apply(edit(false, hash)).await.unwrap();
        assert!(time.sync_now().is_err());
        time.stop().await;
    }
}
