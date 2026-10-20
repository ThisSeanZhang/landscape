use landscape_macro::LdApiError;
use serde::Serialize;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum TimeSyncError {
    #[error("Time sync service is not enabled")]
    #[api_error(id = "time.sync_disabled", status = 409)]
    SyncDisabled,
}

/// Where the current system time comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum TimeSyncSource {
    #[default]
    System,
    Ntp,
}

impl TimeSyncSource {
    pub const fn as_str(&self) -> &'static str {
        match self {
            TimeSyncSource::System => "system",
            TimeSyncSource::Ntp => "ntp",
        }
    }
}

impl std::fmt::Display for TimeSyncSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle stage of the sync loop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum TimeSyncStage {
    #[default]
    Startup,
    Disabled,
    Initial,
    Steady,
    Fallback,
    Error,
}

impl TimeSyncStage {
    pub const fn as_str(&self) -> &'static str {
        match self {
            TimeSyncStage::Startup => "startup",
            TimeSyncStage::Disabled => "disabled",
            TimeSyncStage::Initial => "initial",
            TimeSyncStage::Steady => "steady",
            TimeSyncStage::Fallback => "fallback",
            TimeSyncStage::Error => "error",
        }
    }
}

impl std::fmt::Display for TimeSyncStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the most recent sync attempt did to the clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub enum TimeSyncAction {
    #[default]
    Startup,
    Disabled,
    InitialStep,
    PeriodicStep,
    PeriodicRefresh,
    NtpSetFailed,
    FallbackSystem,
}

impl TimeSyncAction {
    pub const fn as_str(&self) -> &'static str {
        match self {
            TimeSyncAction::Startup => "startup",
            TimeSyncAction::Disabled => "disabled",
            TimeSyncAction::InitialStep => "initial_step",
            TimeSyncAction::PeriodicStep => "periodic_step",
            TimeSyncAction::PeriodicRefresh => "periodic_refresh",
            TimeSyncAction::NtpSetFailed => "ntp_set_failed",
            TimeSyncAction::FallbackSystem => "fallback_system",
        }
    }
}

impl std::fmt::Display for TimeSyncAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct TimeSyncStatus {
    pub enabled: bool,
    pub running: bool,
    pub current_source: TimeSyncSource,
    pub sync_stage: TimeSyncStage,
    pub last_action: TimeSyncAction,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format_matches_legacy_strings() {
        let status = TimeSyncStatus {
            current_source: TimeSyncSource::Ntp,
            sync_stage: TimeSyncStage::Steady,
            last_action: TimeSyncAction::PeriodicStep,
            ..Default::default()
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"current_source\":\"ntp\""));
        assert!(json.contains("\"sync_stage\":\"steady\""));
        assert!(json.contains("\"last_action\":\"periodic_step\""));
    }

    #[test]
    fn defaults_are_startup_values() {
        assert_eq!(TimeSyncSource::default().as_str(), "system");
        assert_eq!(TimeSyncStage::default().as_str(), "startup");
        assert_eq!(TimeSyncAction::default().as_str(), "startup");
    }
}
