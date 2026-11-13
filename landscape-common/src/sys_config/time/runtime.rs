use super::config::LandscapeTimeConfig;
use crate::{
    DEFAULT_TIME_ENABLE, DEFAULT_TIME_SAMPLES_PER_SERVER, DEFAULT_TIME_SERVERS,
    DEFAULT_TIME_STEP_THRESHOLD_MS, DEFAULT_TIME_SYNC_INTERVAL_SECS, DEFAULT_TIME_TIMEOUT_SECS,
};

#[derive(Clone, Debug)]
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
    pub fn update_from_file_config(&mut self, config: &LandscapeTimeConfig) {
        if let Some(v) = config.enabled {
            self.enabled = v;
        }
        if let Some(v) = &config.servers {
            self.servers = v.clone();
        }
        if let Some(v) = config.sync_interval_secs {
            self.sync_interval_secs = v;
        }
        if let Some(v) = config.timeout_secs {
            self.timeout_secs = v;
        }
        if let Some(v) = config.step_threshold_ms {
            self.step_threshold_ms = v;
        }
        if let Some(v) = config.samples_per_server {
            self.samples_per_server = v;
        }
    }
}
