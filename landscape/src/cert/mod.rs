pub mod account_service;
pub mod dns_provider;
pub mod order_service;

use landscape_common::cert::order::{CertConfig, CertStatus, CertType};
use landscape_common::service::controller::ConfigStoreController;
use landscape_common::utils::time::get_f64_timestamp;
use landscape_core::cert::parse_cert_validity_from_pem;
use rcgen::generate_simple_self_signed;
use uuid::Uuid;

use crate::cert::order_service::CertService;

const AUTO_API_FALLBACK_CERT_NAME: &str = "Auto Generated API TLS Certificate";
const AUTO_API_FALLBACK_CERT_DOMAINS: [&str; 2] = ["landscape.local", "*.landscape.local"];

fn auto_api_fallback_domains() -> Vec<String> {
    AUTO_API_FALLBACK_CERT_DOMAINS.iter().map(|domain| domain.to_string()).collect()
}

fn has_expected_auto_api_fallback_domains(domains: &[String]) -> bool {
    let mut actual = domains.to_vec();
    let mut expected = auto_api_fallback_domains();
    actual.sort();
    expected.sort();
    actual == expected
}

fn is_usable_auto_api_fallback_cert(cert: &CertConfig) -> bool {
    cert.name == AUTO_API_FALLBACK_CERT_NAME
        && matches!(cert.status, CertStatus::Valid)
        && cert.certificate.as_ref().is_some()
        && cert.private_key.as_ref().is_some()
        && has_expected_auto_api_fallback_domains(&cert.domains)
}

/// Ensure a usable Manual `for_api` fallback cert exists, generating a new
/// self-signed one when needed; used as the API TLS resolver fallback.
async fn ensure_auto_api_fallback_cert(cert_service: &CertService) -> Result<CertConfig, String> {
    let mut manual_for_api_certs: Vec<CertConfig> = cert_service
        .list()
        .await
        .map_err(|e| e.to_string())?
        .into_iter()
        .filter(|c| c.for_api && matches!(c.cert_type, CertType::Manual))
        .collect();

    manual_for_api_certs.sort_by(|a, b| {
        b.expires_at.partial_cmp(&a.expires_at).unwrap_or(std::cmp::Ordering::Equal).then_with(
            || b.update_at.partial_cmp(&a.update_at).unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    if let Some(existing) = manual_for_api_certs.iter().find(|c| {
        c.name != AUTO_API_FALLBACK_CERT_NAME
            && matches!(c.status, CertStatus::Valid)
            && c.certificate.as_ref().is_some()
            && c.private_key.as_ref().is_some()
    }) {
        return Ok(existing.clone());
    }

    let existing_auto_fallback =
        manual_for_api_certs.into_iter().find(|c| c.name == AUTO_API_FALLBACK_CERT_NAME);

    if let Some(existing) =
        existing_auto_fallback.as_ref().filter(|cert| is_usable_auto_api_fallback_cert(cert))
    {
        return Ok(existing.clone());
    }

    tracing::warn!(
        "No usable manual for_api fallback cert found, generating a new self-signed one"
    );
    let subject_alt_names = auto_api_fallback_domains();
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names.clone())
            .map_err(|e| format!("failed to generate self-signed fallback cert: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let (issued_at, expires_at) = parse_cert_validity_from_pem(&cert_pem);

    let auto_cert = CertConfig {
        id: existing_auto_fallback.as_ref().map(|cert| cert.id).unwrap_or_else(Uuid::new_v4),
        name: AUTO_API_FALLBACK_CERT_NAME.to_string(),
        domains: subject_alt_names,
        status: CertStatus::Valid,
        private_key: Some(key_pem),
        certificate: Some(cert_pem),
        certificate_chain: None,
        expires_at,
        issued_at,
        status_message: None,
        cert_type: CertType::Manual,
        for_api: true,
        for_gateway: false,
        update_at: existing_auto_fallback
            .as_ref()
            .map(|cert| cert.update_at)
            .unwrap_or_else(get_f64_timestamp),
    };

    cert_service
        .checked_set(auto_cert)
        .await
        .map_err(|e| format!("failed to persist auto-generated fallback cert: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_localhost_auto_api_fallback_cert_is_not_reusable() {
        let legacy_cert = CertConfig {
            id: Uuid::new_v4(),
            name: AUTO_API_FALLBACK_CERT_NAME.to_string(),
            domains: vec!["localhost".to_string()],
            status: CertStatus::Valid,
            private_key: Some("key".to_string()),
            certificate: Some("cert".to_string()),
            certificate_chain: None,
            expires_at: None,
            issued_at: None,
            status_message: None,
            cert_type: CertType::Manual,
            for_api: true,
            for_gateway: false,
            update_at: 0.0,
        };

        assert!(!is_usable_auto_api_fallback_cert(&legacy_cert));
    }

    #[test]
    fn expected_auto_api_fallback_cert_is_reusable() {
        let auto_cert = CertConfig {
            id: Uuid::new_v4(),
            name: AUTO_API_FALLBACK_CERT_NAME.to_string(),
            domains: vec!["landscape.local".to_string(), "*.landscape.local".to_string()],
            status: CertStatus::Valid,
            private_key: Some("key".to_string()),
            certificate: Some("cert".to_string()),
            certificate_chain: None,
            expires_at: None,
            issued_at: None,
            status_message: None,
            cert_type: CertType::Manual,
            for_api: true,
            for_gateway: false,
            update_at: 0.0,
        };

        assert!(is_usable_auto_api_fallback_cert(&auto_cert));
    }
}
