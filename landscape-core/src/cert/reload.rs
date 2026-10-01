use std::sync::Arc;

use landscape_common::cert::order::{CertConfig, CertStatus};
use rustls::ServerConfig;
use rustls::sign::CertifiedKey;

use super::pem::{build_certified_key_from_pem, extract_cert_dns_names_from_pem};
use super::resolver::{SharedSniResolver, TlsResolverEntry, build_resolver_snapshot_from_entries};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertUsage {
    Api,
    Gateway,
}

impl CertUsage {
    fn matches_cert(&self, cert: &CertConfig) -> bool {
        match self {
            CertUsage::Api => cert.for_api,
            CertUsage::Gateway => cert.for_gateway,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            CertUsage::Api => "API",
            CertUsage::Gateway => "Gateway",
        }
    }
}

#[async_trait::async_trait]
pub trait CertSnapshotProvider: Send + Sync {
    async fn list_certs(&self) -> Result<Vec<CertConfig>, String>;
}

/// Reload TLS SNI mappings for `usage` from the provider into `shared_resolver`.
/// For `CertUsage::Api` a `fallback` certified key is required (served for
/// unmatched hosts and missing SNI); for `CertUsage::Gateway` pass `None` —
/// if no valid gateway cert exists, the resolver will simply have no entries.
pub async fn reload_tls_resolver(
    provider: &dyn CertSnapshotProvider,
    shared_resolver: &SharedSniResolver,
    usage: CertUsage,
    fallback: Option<CertifiedKey>,
) -> Result<usize, String> {
    let mut candidates: Vec<CertConfig> = provider
        .list_certs()
        .await?
        .into_iter()
        .filter(|c| {
            usage.matches_cert(c)
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

    if matches!(usage, CertUsage::Api) && candidates.len() > 1 {
        tracing::info!("Multiple for_api certs found ({})", candidates.len());
    }

    let mut tls_entries = Vec::new();
    for cert in candidates {
        let cert_pem = cert.certificate.as_deref().unwrap_or_default();
        let key_pem = cert.private_key.as_deref().unwrap_or_default();
        let chain_pem = cert.certificate_chain.as_deref();
        let cert_names = match extract_cert_dns_names_from_pem(cert_pem) {
            Ok(names) => names,
            Err(e) => {
                tracing::warn!("Skip invalid cert '{}' ({})", cert.name, e);
                continue;
            }
        };
        match build_certified_key_from_pem(cert_pem, chain_pem, key_pem) {
            Ok(ck) => tls_entries.push(TlsResolverEntry {
                cert_name: cert.name.clone(),
                configured_domains: cert.domains.clone(),
                cert_names,
                certified_key: ck,
            }),
            Err(e) => tracing::warn!("Skip invalid cert '{}' ({})", cert.name, e),
        }
    }

    let (snapshot, inserted_count) = build_resolver_snapshot_from_entries(tls_entries, fallback);
    shared_resolver.swap(snapshot);
    tracing::info!("Loaded {inserted_count} SNI domain mappings for {} TLS", usage.label());
    Ok(inserted_count)
}

pub fn build_tls_server_config_with_shared_resolver(
    shared_resolver: SharedSniResolver,
) -> ServerConfig {
    let mut config =
        ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(shared_resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
}
