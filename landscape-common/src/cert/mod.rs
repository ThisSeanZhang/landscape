pub mod account;
pub mod order;

use landscape_macro::LdApiError;

use crate::config::ConfigId;
use crate::database::error::DbError;

#[derive(thiserror::Error, Debug, LdApiError)]
#[api_error(crate_path = "crate")]
pub enum CertError {
    #[error("Certificate account '{0}' not found")]
    #[api_error(id = "cert.account_not_found", status = 404)]
    AccountNotFound(ConfigId),

    #[error("Certificate '{0}' not found")]
    #[api_error(id = "cert.cert_not_found", status = 404)]
    CertNotFound(ConfigId),

    #[error("DNS provider profile '{0}' not found")]
    #[api_error(id = "cert.provider_profile_not_found", status = 404)]
    DnsProviderProfileNotFound(ConfigId),

    #[error("ACME registration failed: {0}")]
    #[api_error(id = "cert.registration_failed", status = 500)]
    RegistrationFailed(String),

    #[error("ACME deactivation failed: {0}")]
    #[api_error(id = "cert.deactivation_failed", status = 500)]
    DeactivationFailed(String),

    #[error("ACME account verification failed: {0}")]
    #[api_error(id = "cert.verification_failed", status = 500)]
    VerificationFailed(String),

    #[error("Provider does not support staging environment")]
    #[api_error(id = "cert.staging_not_supported", status = 400)]
    StagingNotSupported,

    #[error("Operation not allowed in current status: {0}")]
    #[api_error(id = "cert.invalid_status_transition", status = 409)]
    InvalidStatusTransition(String),

    #[error("Cannot mutate account while active/renewable certificates exist: {0}")]
    #[api_error(id = "cert.account_has_active_certificates", status = 409)]
    AccountHasActiveCertificates(String),

    #[error("Cannot change ACME account while certificate is valid; revoke it first")]
    #[api_error(id = "cert.acme_account_change_requires_revocation", status = 409)]
    AcmeAccountChangeRequiresRevocation,

    #[error("Certificate issuance failed: {0}")]
    #[api_error(id = "cert.issuance_failed", status = 500)]
    IssuanceFailed(String),

    #[error("Certificate revocation failed: {0}")]
    #[api_error(id = "cert.revocation_failed", status = 500)]
    RevocationFailed(String),

    #[error("DNS challenge setup failed: {0}")]
    #[api_error(id = "cert.dns_challenge_failed", status = 500)]
    DnsChallengeSetupFailed(String),

    #[error(transparent)]
    #[api_error(transparent)]
    Internal(#[from] DbError),
}
