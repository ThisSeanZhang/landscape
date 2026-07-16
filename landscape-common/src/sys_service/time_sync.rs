use serde::Serialize;

#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TimeSyncStatus {
    pub enabled: bool,
    pub running: bool,
    pub current_source: String,
    pub sync_stage: String,
    pub last_action: String,
    pub last_attempt_at: Option<f64>,
    pub last_success_at: Option<f64>,
    pub last_system_clock_update_at: Option<f64>,
    pub last_server: Option<String>,
    pub last_offset_ms: Option<f64>,
    pub last_delay_ms: Option<f64>,
    pub selected_sample_count: Option<u8>,
    pub last_error: Option<String>,
    pub system_clock_synced: bool,
    pub next_attempt_in_secs: Option<u64>,
}
