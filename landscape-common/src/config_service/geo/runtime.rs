use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GeoSourceKind {
    Ip,
    Site,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum GeoTaskPhase {
    Downloading,
    Verifying,
    Parsing,
    Applying,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GeoTaskProgress {
    pub source_id: Uuid,
    pub kind: GeoSourceKind,
    pub phase: GeoTaskPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    // TODO: `phase_detail` is never populated, so a task failure cannot be
    // reported to the UI; the error is only visible in the server log.
    pub phase_detail: Option<String>,
    #[serde(default)]
    pub bytes_done: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub bytes_total: Option<u64>,
    pub started_at: f64,
    pub updated_at: f64,
}

impl GeoTaskProgress {
    pub fn new(source_id: Uuid, kind: GeoSourceKind, phase: GeoTaskPhase) -> Self {
        let now = get_f64_timestamp();
        Self {
            source_id,
            kind,
            phase,
            phase_detail: None,
            bytes_done: 0,
            bytes_total: None,
            started_at: now,
            updated_at: now,
        }
    }

    pub fn advance(&mut self, phase: GeoTaskPhase) {
        self.phase = phase;
        self.phase_detail = None;
        self.bytes_done = 0;
        self.bytes_total = None;
        self.updated_at = get_f64_timestamp();
    }

    pub fn set_download_progress(&mut self, bytes_done: u64, bytes_total: Option<u64>) {
        self.bytes_done = bytes_done;
        self.bytes_total = bytes_total;
        self.updated_at = get_f64_timestamp();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_task_progress_timestamps_use_milliseconds() {
        let mut progress =
            GeoTaskProgress::new(Uuid::new_v4(), GeoSourceKind::Ip, GeoTaskPhase::Downloading);
        assert!(progress.started_at > 1_000_000_000_000.0);
        progress.advance(GeoTaskPhase::Parsing);
        assert!(progress.updated_at >= progress.started_at);
        assert!(progress.updated_at > 1_000_000_000_000.0);
        assert_eq!(progress.bytes_done, 0);
        assert!(progress.bytes_total.is_none());
    }

    #[test]
    fn download_progress_updates_bytes_and_timestamp() {
        let mut progress =
            GeoTaskProgress::new(Uuid::new_v4(), GeoSourceKind::Site, GeoTaskPhase::Downloading);
        progress.set_download_progress(1024, Some(4096));
        assert_eq!(progress.bytes_done, 1024);
        assert_eq!(progress.bytes_total, Some(4096));
        assert!(progress.updated_at >= progress.started_at);
    }
}
