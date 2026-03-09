use std::collections::HashSet;
use std::sync::Arc;

use crate::config_service::cert::CertService;
use arc_swap::ArcSwapOption;
use landscape_common::cert::order::{CertConfig, CertStatus, CertType};
use landscape_common::service::controller::ConfigController;
use landscape_common::utils::time::get_f64_timestamp;
use pem::parse_many;
use rcgen::generate_simple_self_signed;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use uuid::Uuid;

const AUTO_API_FALLBACK_CERT_NAME: &str = "Auto Generated API TLS Certificate";

#[derive(Debug, Clone, Default)]
pub struct SharedSniResolver {
    inner: Arc<ArcSwapOption<ResolvesServerCertUsingSni>>,
    fallback: Arc<ArcSwapOption<CertifiedKey>>,
}

impl SharedSniResolver {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ArcSwapOption::new(None)),
            fallback: Arc::new(ArcSwapOption::new(None)),
        }
    }

    pub fn swap(&self, resolver: ResolvesServerCertUsingSni) {
        self.inner.store(Some(Arc::new(resolver)));
    }

    pub fn set_fallback(&self, fallback: CertifiedKey) {
        self.fallback.store(Some(Arc::new(fallback)));
    }
}

impl ResolvesServerCert for SharedSniResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(resolver) = self.inner.load_full() {
            if let Some(cert) = resolver.resolve(client_hello) {
                return Some(cert);
            }
        }
        self.fallback.load_full()
    }
}

/// Reload Gateway TLS SNI mappings from cert manager (`for_gateway=true`) into `shared_resolver`.
/// Unlike API TLS, no fallback self-signed cert is generated — if no valid gateway cert exists,
/// the resolver will simply have no entries.
pub async fn reload_gateway_tls_resolver(
    cert_service: &CertService,
    shared_resolver: &SharedSniResolver,
) -> Result<usize, String> {
    let mut candidates: Vec<CertConfig> = cert_service
        .list()
        .await
        .into_iter()
        .filter(|c| {
            c.for_gateway
                && matches!(c.status, CertStatus::Valid)
                && c.certificate.as_ref().is_some()
                && c.private_key.as_ref().is_some()
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.expires_at.partial_cmp(&a.expires_at).unwrap_or(std::cmp::Ordering::Equal).then_with(
            || b.update_at.partial_cmp(&a.update_at).unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    let mut tls_entries: Vec<(String, Vec<String>, CertifiedKey)> = Vec::new();
    for cert in candidates {
        let cert_pem = cert.certificate.as_deref().unwrap_or_default();
        let key_pem = cert.private_key.as_deref().unwrap_or_default();
        let chain_pem = cert.certificate_chain.as_deref();
        match build_certified_key_from_pem(cert_pem, chain_pem, key_pem) {
            Ok(ck) => {
                tls_entries.push((cert.name.clone(), cert.domains.clone(), ck));
            }
            Err(e) => {
                tracing::warn!("Skip invalid for_gateway cert '{}' ({})", cert.name, e);
            }
        }
    }

    let (resolver, inserted_count) = build_sni_resolver_from_entries(tls_entries);
    shared_resolver.swap(resolver);
    tracing::info!("Loaded {inserted_count} SNI domain mappings for Gateway TLS");
    Ok(inserted_count)
}

/// Reload API TLS SNI mappings from cert manager (`for_api=true`) into `shared_resolver`.
/// Ensures an auto-generated Manual `for_api` cert exists and uses it as fallback.
pub async fn reload_api_tls_resolver(
    cert_service: &CertService,
    shared_resolver: &SharedSniResolver,
) -> Result<usize, String> {
    let fallback_cert = ensure_auto_api_fallback_cert(cert_service).await?;

    let mut candidates: Vec<CertConfig> = cert_service
        .list()
        .await
        .into_iter()
        .filter(|c| {
            c.for_api
                && matches!(c.status, CertStatus::Valid)
                && c.certificate.as_ref().is_some()
                && c.private_key.as_ref().is_some()
        })
        .collect();

    candidates.sort_by(|a, b| {
        b.expires_at.partial_cmp(&a.expires_at).unwrap_or(std::cmp::Ordering::Equal).then_with(
            || b.update_at.partial_cmp(&a.update_at).unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    if candidates.len() > 1 {
        tracing::info!("Multiple for_api certs found ({})", candidates.len());
    }

    let mut tls_entries: Vec<(String, Vec<String>, CertifiedKey)> = Vec::new();
    for cert in candidates {
        let cert_pem = cert.certificate.as_deref().unwrap_or_default();
        let key_pem = cert.private_key.as_deref().unwrap_or_default();
        let chain_pem = cert.certificate_chain.as_deref();
        match build_certified_key_from_pem(cert_pem, chain_pem, key_pem) {
            Ok(ck) => {
                tls_entries.push((cert.name.clone(), cert.domains.clone(), ck));
            }
            Err(e) => {
                tracing::warn!("Skip invalid for_api cert '{}' ({})", cert.name, e);
            }
        }
    }

    let fallback_ck = build_certified_key_from_pem(
        fallback_cert.certificate.as_deref().unwrap_or_default(),
        fallback_cert.certificate_chain.as_deref(),
        fallback_cert.private_key.as_deref().unwrap_or_default(),
    )
    .map_err(|e| format!("failed to build fallback API TLS cert: {e}"))?;
    shared_resolver.set_fallback(fallback_ck);

    let (resolver, inserted_count) = build_sni_resolver_from_entries(tls_entries);
    shared_resolver.swap(resolver);
    tracing::info!("Loaded {inserted_count} SNI domain mappings for API TLS");
    Ok(inserted_count)
}

pub fn build_tls_server_config_with_shared_resolver(
    shared_resolver: SharedSniResolver,
) -> ServerConfig {
    ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(shared_resolver))
}

pub fn validate_certified_key_from_pem(
    cert_pem: &str,
    chain_pem: Option<&str>,
    key_pem: &str,
) -> Result<(), String> {
    build_certified_key_from_pem(cert_pem, chain_pem, key_pem).map(|_| ())
}

fn parse_cert_validity_from_pem(cert_pem: &str) -> (Option<f64>, Option<f64>) {
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

fn build_sni_resolver_from_entries(
    entries: Vec<(String, Vec<String>, CertifiedKey)>,
) -> (ResolvesServerCertUsingSni, usize) {
    let mut resolver = ResolvesServerCertUsingSni::new();
    let mut inserted_names: HashSet<String> = HashSet::new();
    let mut inserted_count = 0usize;

    for (cert_name, domains, certified_key) in entries {
        let normalized_domains: Vec<String> = domains
            .into_iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        for domain in normalized_domains {
            if !inserted_names.insert(domain.clone()) {
                continue;
            }
            if let Err(e) = resolver.add(&domain, certified_key.clone()) {
                tracing::warn!(
                    "Skip SNI mapping domain '{}' for cert '{}' ({})",
                    domain,
                    cert_name,
                    e
                );
                continue;
            }
            inserted_count += 1;
        }
    }

    (resolver, inserted_count)
}

fn build_certified_key_from_pem(
    cert_pem: &str,
    chain_pem: Option<&str>,
    key_pem: &str,
) -> Result<CertifiedKey, String> {
    let mut full_cert = cert_pem.to_string();
    if let Some(chain) = chain_pem {
        if !chain.trim().is_empty() {
            full_cert.push('\n');
            full_cert.push_str(chain);
        }
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
            _ => None,
        })
        .ok_or_else(|| "no valid private key found".to_string())?;

    let provider = CryptoProvider::get_default()
        .ok_or_else(|| "rustls crypto provider is not installed".to_string())?;

    CertifiedKey::from_der(certs, private_key, provider)
        .map_err(|e| format!("invalid certified key: {e}"))
}

async fn ensure_auto_api_fallback_cert(cert_service: &CertService) -> Result<CertConfig, String> {
    let mut manual_for_api_certs: Vec<CertConfig> = cert_service
        .list()
        .await
        .into_iter()
        .filter(|c| c.for_api && matches!(c.cert_type, CertType::Manual))
        .collect();

    manual_for_api_certs.sort_by(|a, b| {
        b.expires_at.partial_cmp(&a.expires_at).unwrap_or(std::cmp::Ordering::Equal).then_with(
            || b.update_at.partial_cmp(&a.update_at).unwrap_or(std::cmp::Ordering::Equal),
        )
    });

    if let Some(existing) = manual_for_api_certs.into_iter().find(|c| {
        matches!(c.status, CertStatus::Valid)
            && c.certificate.as_ref().is_some()
            && c.private_key.as_ref().is_some()
    }) {
        return Ok(existing);
    }

    tracing::warn!(
        "No usable manual for_api fallback cert found, generating a new self-signed one"
    );
    let subject_alt_names = vec!["localhost".to_string()];
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(subject_alt_names.clone())
            .map_err(|e| format!("failed to generate self-signed fallback cert: {e}"))?;

    let cert_pem = cert.pem();
    let key_pem = signing_key.serialize_pem();
    let (issued_at, expires_at) = parse_cert_validity_from_pem(&cert_pem);

    let auto_cert = CertConfig {
        id: Uuid::new_v4(),
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
        update_at: get_f64_timestamp(),
    };

    cert_service
        .checked_set(auto_cert)
        .await
        .map_err(|e| format!("failed to persist auto-generated fallback cert: {e}"))
}
