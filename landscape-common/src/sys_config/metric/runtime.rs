use super::config::{LandscapeMetricConfig, MetricMode};
use super::{cleanup_budget_secs_to_ms, metric_db_max_mb_to_bytes};

#[derive(Clone, Debug)]
pub struct MetricRuntimeConfig {
    pub mode: MetricMode,
    pub connect_second_window_minutes: u64,
    pub connect_1m_retention_days: u64,
    pub connect_1h_retention_days: u64,
    pub connect_1d_retention_days: u64,
    pub connect_summary_retention_days: u64,
    pub connect_summary_max_rows: u64,
    pub connect_db_max_bytes: u64,
    pub dns_retention_days: u64,
    pub dns_1m_retention_days: u64,
    pub dns_db_max_bytes: u64,
    pub write_batch_size: usize,
    pub write_flush_interval_secs: u64,
    pub cleanup_interval_secs: u64,
    pub cleanup_time_budget_ms: u64,
    pub cleanup_slice_window_secs: u64,
}

impl MetricRuntimeConfig {
    pub fn update_from_file_config(&mut self, config: &LandscapeMetricConfig) {
        if let Some(v) = &config.mode {
            self.mode = v.clone();
        }
        if let Some(v) = config.connect_second_window_minutes {
            self.connect_second_window_minutes = v;
        }
        if let Some(v) = config.connect_1m_retention_days {
            self.connect_1m_retention_days = v;
        }
        if let Some(v) = config.connect_1h_retention_days {
            self.connect_1h_retention_days = v;
        }
        if let Some(v) = config.connect_1d_retention_days {
            self.connect_1d_retention_days = v;
        }
        if let Some(v) = config.connect_summary_retention_days {
            self.connect_summary_retention_days = v;
        }
        if let Some(v) = config.connect_summary_max_rows {
            self.connect_summary_max_rows = v;
        }
        if let Some(v) = config.connect_db_max_mb {
            self.connect_db_max_bytes = metric_db_max_mb_to_bytes(v);
        }
        if let Some(v) = config.dns_retention_days {
            self.dns_retention_days = v;
        }
        if let Some(v) = config.dns_1m_retention_days {
            self.dns_1m_retention_days = v;
        }
        if let Some(v) = config.dns_db_max_mb {
            self.dns_db_max_bytes = metric_db_max_mb_to_bytes(v);
        }
        if let Some(v) = config.write_batch_size {
            self.write_batch_size = v;
        }
        if let Some(v) = config.write_flush_interval_secs {
            self.write_flush_interval_secs = v;
        }
        if let Some(v) = config.cleanup_interval_secs {
            self.cleanup_interval_secs = v;
        }
        if let Some(v) = config.cleanup_time_budget_secs {
            self.cleanup_time_budget_ms = cleanup_budget_secs_to_ms(v);
        }
        if let Some(v) = config.cleanup_slice_window_secs {
            self.cleanup_slice_window_secs = v;
        }
    }
}
