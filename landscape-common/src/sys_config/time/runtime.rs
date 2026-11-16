use super::config::LandscapeTimeConfig;
use crate::{
    DEFAULT_TIME_ENABLE, DEFAULT_TIME_SAMPLES_PER_SERVER, DEFAULT_TIME_SERVERS,
    DEFAULT_TIME_STEP_THRESHOLD_MS, DEFAULT_TIME_SYNC_INTERVAL_SECS, DEFAULT_TIME_TIMEOUT_SECS,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeRuntimeConfig {
    pub enabled: bool,
    pub servers: Vec<String>,
    pub sync_interval_secs: u64,
    pub timeout_secs: u64,
    pub step_threshold_ms: u64,
    pub samples_per_server: u8,
}

impl Default for TimeRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_TIME_ENABLE,
            servers: DEFAULT_TIME_SERVERS.iter().map(|server| (*server).to_string()).collect(),
            sync_interval_secs: DEFAULT_TIME_SYNC_INTERVAL_SECS,
            timeout_secs: DEFAULT_TIME_TIMEOUT_SECS,
            step_threshold_ms: DEFAULT_TIME_STEP_THRESHOLD_MS,
            samples_per_server: DEFAULT_TIME_SAMPLES_PER_SERVER,
        }
    }
}

impl TimeRuntimeConfig {
    /// Build a complete runtime configuration; omitted fields use defaults.
    pub fn from_file_config(config: &LandscapeTimeConfig) -> Self {
        let defaults = Self::default();
        Self {
            enabled: config.enabled.unwrap_or(defaults.enabled),
            servers: config.servers.clone().unwrap_or(defaults.servers),
            sync_interval_secs: config.sync_interval_secs.unwrap_or(defaults.sync_interval_secs),
            timeout_secs: config.timeout_secs.unwrap_or(defaults.timeout_secs),
            step_threshold_ms: config.step_threshold_ms.unwrap_or(defaults.step_threshold_ms),
            samples_per_server: config
                .samples_per_server
                .unwrap_or(defaults.samples_per_server)
                .max(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_fields_restores_defaults_after_file_round_trip() {
        let mut file_config = LandscapeTimeConfig {
            enabled: Some(true),
            servers: Some(vec!["custom:123".into()]),
            sync_interval_secs: Some(123),
            timeout_secs: Some(10),
            step_threshold_ms: Some(0),
            samples_per_server: Some(5),
        };
        let customized = TimeRuntimeConfig::from_file_config(&file_config);
        file_config = LandscapeTimeConfig::default();
        let updated = TimeRuntimeConfig::from_file_config(&file_config);
        let saved = toml::to_string(&file_config).unwrap();
        let reloaded: LandscapeTimeConfig = toml::from_str(&saved).unwrap();
        let restarted = TimeRuntimeConfig::from_file_config(&reloaded);
        assert_eq!(updated, restarted);
        assert_ne!(customized, updated);
        assert_eq!(updated.servers, TimeRuntimeConfig::default().servers);
        assert_eq!(
            TimeRuntimeConfig::from_file_config(&LandscapeTimeConfig {
                samples_per_server: Some(0),
                ..Default::default()
            })
            .samples_per_server,
            1
        );
    }
}
