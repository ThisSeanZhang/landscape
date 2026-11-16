use super::config::LandscapeTimeConfig;
use crate::sys_config::{RuntimeConfigSource, runtime::warn_repair};
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
    /// Defend all service entrypoints, including callers that construct runtime directly.
    pub fn normalized(mut self) -> Self {
        for (field, value) in [
            ("sync_interval_secs", self.sync_interval_secs),
            ("timeout_secs", self.timeout_secs),
            ("samples_per_server", u64::from(self.samples_per_server)),
        ] {
            if value == 0 {
                warn_repair("time", field, "0 must be at least 1", "raised to minimum", 1);
            }
        }
        self.sync_interval_secs = self.sync_interval_secs.max(1);
        self.timeout_secs = self.timeout_secs.max(1);
        self.samples_per_server = self.samples_per_server.max(1);
        self
    }
}

impl RuntimeConfigSource for LandscapeTimeConfig {
    type Runtime = TimeRuntimeConfig;
    type Error = crate::sys_service::time_sync::TimeSyncError;

    fn validate(&self) -> Result<(), Self::Error> {
        // Zero timing values have historically been normalized to one, not rejected.
        Ok(())
    }

    fn build_runtime(&self) -> Self::Runtime {
        let defaults = TimeRuntimeConfig::default();
        TimeRuntimeConfig {
            enabled: self.enabled.unwrap_or(defaults.enabled),
            servers: self.servers.clone().unwrap_or(defaults.servers),
            sync_interval_secs: self.sync_interval_secs.unwrap_or(defaults.sync_interval_secs),
            timeout_secs: self.timeout_secs.unwrap_or(defaults.timeout_secs),
            step_threshold_ms: self.step_threshold_ms.unwrap_or(defaults.step_threshold_ms),
            samples_per_server: self.samples_per_server.unwrap_or(defaults.samples_per_server),
        }
        .normalized()
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
        let customized = file_config.to_runtime().unwrap();
        file_config = LandscapeTimeConfig::default();
        let updated = file_config.to_runtime().unwrap();
        let saved = toml::to_string(&file_config).unwrap();
        let reloaded: LandscapeTimeConfig = toml::from_str(&saved).unwrap();
        let restarted = reloaded.to_runtime().unwrap();
        assert_eq!(updated, restarted);
        assert_ne!(customized, updated);
        assert_eq!(updated.servers, TimeRuntimeConfig::default().servers);
        assert_eq!(
            (LandscapeTimeConfig { samples_per_server: Some(0), ..Default::default() })
                .to_runtime()
                .unwrap()
                .samples_per_server,
            1
        );
    }
    #[test]
    fn conversion_normalizes_all_zero_timing_fields() {
        let config = LandscapeTimeConfig {
            sync_interval_secs: Some(0),
            timeout_secs: Some(0),
            samples_per_server: Some(0),
            step_threshold_ms: Some(0),
            ..Default::default()
        };
        let runtime = config.to_runtime().unwrap();
        assert_eq!(runtime.sync_interval_secs, 1);
        assert_eq!(runtime.timeout_secs, 1);
        assert_eq!(runtime.samples_per_server, 1);
        assert_eq!(runtime.step_threshold_ms, 0);
    }
    #[test]
    fn normalization_is_idempotent_and_preserves_other_fields() {
        let runtime = TimeRuntimeConfig {
            enabled: false,
            servers: vec!["custom:123".into()],
            sync_interval_secs: 0,
            timeout_secs: 0,
            samples_per_server: 0,
            step_threshold_ms: 0,
        }
        .normalized();
        assert_eq!(runtime.clone().normalized(), runtime);
        assert_eq!(runtime.sync_interval_secs, 1);
        assert_eq!(runtime.timeout_secs, 1);
        assert_eq!(runtime.samples_per_server, 1);
        assert!(!runtime.enabled);
        assert_eq!(runtime.servers, vec!["custom:123"]);
        assert_eq!(runtime.step_threshold_ms, 0);
    }
}
