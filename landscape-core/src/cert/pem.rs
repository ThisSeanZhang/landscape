use std::collections::HashSet;

use pem::parse_many;
use rustls::crypto::CryptoProvider;
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use super::resolver::normalize_domain_name;

pub fn validate_certified_key_from_pem(
    cert_pem: &str,
    chain_pem: Option<&str>,
    key_pem: &str,
) -> Result<(), String> {
    build_certified_key_from_pem(cert_pem, chain_pem, key_pem).map(|_| ())
}

pub fn parse_cert_validity_from_pem(cert_pem: &str) -> (Option<f64>, Option<f64>) {
    let Ok(pem_obj) = pem::parse(cert_pem) else {
        return (None, None);
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(pem_obj.contents()) else {
        return (None, None);
    };
    (
        Some(cert.validity().not_before.timestamp() as f64),
        Some(cert.validity().not_after.timestamp() as f64),
    )
}

pub fn extract_cert_dns_names_from_pem(cert_pem: &str) -> Result<Vec<String>, String> {
    let pem_obj =
        pem::parse(cert_pem).map_err(|e| format!("failed to parse certificate PEM: {e}"))?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem_obj.contents())
        .map_err(|e| format!("failed to parse X.509 certificate: {e}"))?;

    let mut names = Vec::new();
    let mut seen = HashSet::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name
                    && let Some(normalized) = normalize_domain_name(dns)
                    && seen.insert(normalized.clone())
                {
                    names.push(normalized);
                }
            }
        }
    }

    if names.is_empty()
        && let Some(cn) = cert.subject().iter_common_name().next()
        && let Ok(cn_str) = cn.as_str()
        && let Some(normalized) = normalize_domain_name(cn_str)
    {
        names.push(normalized);
    }

    Ok(names)
}

pub fn build_certified_key_from_pem(
    cert_pem: &str,
    chain_pem: Option<&str>,
    key_pem: &str,
) -> Result<CertifiedKey, String> {
    let mut full_cert = cert_pem.to_string();
    if let Some(chain) = chain_pem
        && !chain.trim().is_empty()
    {
        full_cert.push('\n');
        full_cert.push_str(chain);
    }

    let cert_pems =
        parse_many(full_cert.as_bytes()).map_err(|e| format!("failed to parse cert PEM: {e}"))?;
    let certs: Vec<CertificateDer> = cert_pems
        .into_iter()
        .filter(|p| p.tag() == "CERTIFICATE")
        .map(|p| CertificateDer::from(p.contents().to_vec()))
        .collect();
    if certs.is_empty() {
        return Err("no valid certificate found".to_string());
    }

    let key_pems =
        parse_many(key_pem.as_bytes()).map_err(|e| format!("failed to parse key PEM: {e}"))?;
    let private_key = key_pems
        .into_iter()
        .find_map(|p| match p.tag() {
            "PRIVATE KEY" => Some(PrivateKeyDer::Pkcs8(p.contents().to_vec().into())),
            "RSA PRIVATE KEY" => Some(PrivateKeyDer::Pkcs1(p.contents().to_vec().into())),
            "EC PRIVATE KEY" => Some(PrivateKeyDer::Sec1(p.contents().to_vec().into())),
            _ => None,
        })
        .ok_or_else(|| "no valid private key found".to_string())?;

    let provider = CryptoProvider::get_default()
        .ok_or_else(|| "rustls crypto provider is not installed".to_string())?;

    CertifiedKey::from_der(certs, private_key, provider)
        .map_err(|e| format!("invalid certified key: {e}"))
}
