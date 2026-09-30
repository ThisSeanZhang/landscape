use serde::{Deserialize, Serialize};

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
