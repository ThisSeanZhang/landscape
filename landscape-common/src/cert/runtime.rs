use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::utils::time::get_f64_timestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CertIssuePhase {
    ResolvingAccount,
    CreatingDnsRecord,
    WaitingDnsPropagation,
    NotifyingChallenges,
    WaitingValidation,
    Finalizing,
    FetchingCertificate,
    CleaningUpDns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertTaskProgress {
    pub cert_id: Uuid,
    pub phase: CertIssuePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub phase_detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub phase_deadline: Option<f64>,
    pub started_at: f64,
    pub updated_at: f64,
}

impl CertTaskProgress {
    pub fn new(cert_id: Uuid) -> Self {
        let now = get_f64_timestamp();
        Self {
            cert_id,
            phase: CertIssuePhase::ResolvingAccount,
            phase_detail: None,
            phase_deadline: None,
            started_at: now,
            updated_at: now,
        }
    }

    pub fn advance(
        &mut self,
        phase: CertIssuePhase,
        detail: Option<String>,
        deadline: Option<f64>,
    ) {
        self.phase = phase;
        self.phase_detail = detail;
        self.phase_deadline = deadline;
        self.updated_at = get_f64_timestamp();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_task_progress_timestamps_use_milliseconds() {
        let mut progress = CertTaskProgress::new(Uuid::new_v4());
        assert!(progress.started_at > 1_000_000_000_000.0);
        progress.advance(CertIssuePhase::WaitingValidation, None, None);
        assert!(progress.updated_at >= progress.started_at);
        assert!(progress.updated_at > 1_000_000_000_000.0);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CertParsedInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub subject_alt_names: Vec<String>,
    pub signature_algorithm: String,
    pub not_before: f64,
    pub not_after: f64,
    pub fingerprint_sha256: String,
}
