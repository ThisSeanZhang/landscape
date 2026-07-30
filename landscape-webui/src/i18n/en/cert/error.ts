export default {
  "cert.account_not_found": "Certificate account not found (ID: {0})",
  "cert.cert_not_found": "Certificate not found (ID: {0})",
  "cert.provider_profile_not_found": "DNS provider profile not found (ID: {0})",
  "cert.registration_failed": "ACME account registration failed: {0}",
  "cert.deactivation_failed": "ACME account deactivation failed: {0}",
  "cert.verification_failed": "ACME account verification failed: {0}",
  "cert.staging_not_supported":
    "Current ACME provider does not support staging",
  "cert.invalid_status_transition":
    "Operation is not allowed in current status: {0}",
  "cert.account_has_active_certificates":
    "This account still has active or renewable certificates. Revoke them first: {0}",
  "cert.issuance_failed": "Certificate issuance failed: {0}",
  "cert.revocation_failed": "Certificate revocation failed: {0}",
  "cert.dns_challenge_failed": "DNS challenge setup failed: {0}",
  "cert.acme_account_change_requires_revocation":
    "Cannot change ACME account while certificate is valid; revoke it first",
};
