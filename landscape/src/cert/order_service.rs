use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::cert::{
    extract_cert_dns_names_from_pem, reload_api_tls_resolver, reload_gateway_tls_resolver,
    validate_certified_key_from_pem, SharedSniResolver,
};
use crate::dns::redirect_service::DNSRedirectService;
use chrono::{Datelike, Duration as ChronoDuration, Utc};
use instant_acme::{
    Account, ChallengeType as AcmeChallengeType, Identifier, NewOrder, OrderStatus, RetryPolicy,
    RevocationRequest,
};
use landscape_common::cert::account::AccountStatus;
use landscape_common::cert::order::{
    AcmeCertConfig, CertConfig, CertParsedInfo, CertStatus, CertType, ChallengeType,
};
use landscape_common::cert::CertError;
use landscape_common::database::LandscapeStore;
use landscape_common::dns::provider_profile::DnsProviderProfile;
use landscape_common::dns::redirect::{
    DnsRedirectAnswerMode, DynamicDnsMatch, DynamicDnsRedirectBatch, DynamicDnsRedirectRecord,
    DynamicDnsRedirectScope, DEFAULT_BLOCK_METADATA_QUERIES, DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
};
use landscape_common::service::controller::ConfigController;
use landscape_database::cert::repository::CertRepository;
use landscape_database::dns_provider_profile::repository::DnsProviderProfileRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use rcgen::{
    date_time_ymd, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
};
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::account_service::CertAccountService;
use super::dns_provider;

const API_CERT_DYNAMIC_DNS_REDIRECT_SOURCE_ID: &str = "cert-api-local-ips";

#[derive(Clone)]
pub struct CertService {
    store: CertRepository,
    account_service: CertAccountService,
    profile_store: DnsProviderProfileRepository,
    api_tls_resolver: SharedSniResolver,
    gateway_tls_resolver: SharedSniResolver,
    api_dns_redirect_service: Option<DNSRedirectService>,
    tasks: Arc<Mutex<HashMap<Uuid, CertIssueTask>>>,
}

#[derive(Clone)]
struct CertIssueTask {
    cancel: CancellationToken,
}

enum DoIssueResult {
    Issued { private_key_pem: String, cert_chain_pem: String, expires_at: f64 },
    Cancelled,
}

struct GeneratedCertMaterial {
    private_key_pem: String,
    certificate_pem: String,
    issued_at: f64,
    expires_at: f64,
}

impl CertService {
    const ACCOUNT_STATUS_HINT_PREFIX: &'static str = "ACME account status:";

    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        account_service: CertAccountService,
        api_dns_redirect_service: Option<DNSRedirectService>,
    ) -> Self {
        let store = store_provider.cert_store();
        let service = Self {
            store,
            account_service,
            profile_store: store_provider.dns_provider_profile_store(),
            api_tls_resolver: SharedSniResolver::new(),
            gateway_tls_resolver: SharedSniResolver::new(),
            api_dns_redirect_service,
            tasks: Arc::new(Mutex::new(HashMap::new())),
        };

        // Startup resume: re-trigger ACME certs stuck in Processing
        let certs = service.list().await;
        for cert in certs {
            if matches!(cert.status, CertStatus::Processing) {
                if let CertType::Acme(_) = &cert.cert_type {
                    let svc = service.clone();
                    let id = cert.id;
                    tracing::info!("Resuming issuance for cert {id}");
                    tokio::spawn(async move {
                        if let Err(e) = svc.enqueue_issuance_task(id).await {
                            tracing::error!("Failed to resume cert {id}: {e}");
                        }
                    });
                }
            }
        }

        // Auto-renewal background task: check every hour
        {
            let svc = service.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    svc.check_auto_renewals().await;
                }
            });
        }

        service
    }

    pub fn api_tls_resolver(&self) -> SharedSniResolver {
        self.api_tls_resolver.clone()
    }

    pub fn gateway_tls_resolver(&self) -> SharedSniResolver {
        self.gateway_tls_resolver.clone()
    }

    pub async fn reload_api_tls_mapping(&self) -> Result<usize, CertError> {
        let inserted_count = reload_api_tls_resolver(self, &self.api_tls_resolver)
            .await
            .map_err(CertError::IssuanceFailed)?;
        self.sync_api_dynamic_dns_redirects().await;
        Ok(inserted_count)
    }

    pub async fn reload_gateway_tls_mapping(&self) -> Result<usize, CertError> {
        reload_gateway_tls_resolver(self, &self.gateway_tls_resolver)
            .await
            .map_err(CertError::IssuanceFailed)
    }

    async fn set_and_notify(&self, config: CertConfig) -> CertConfig {
        let saved = self.set(config).await;
        if let Err(e) = self.reload_api_tls_mapping().await {
            tracing::warn!("Failed to reload API TLS mapping after cert update: {e}");
        }
        if let Err(e) = self.reload_gateway_tls_mapping().await {
            tracing::warn!("Failed to reload Gateway TLS mapping after cert update: {e}");
        }
        saved
    }

    pub async fn delete_with_notify(&self, id: Uuid) {
        self.delete(id).await;
        if let Err(e) = self.reload_api_tls_mapping().await {
            tracing::warn!("Failed to reload API TLS mapping after cert delete: {e}");
        }
        if let Err(e) = self.reload_gateway_tls_mapping().await {
            tracing::warn!("Failed to reload Gateway TLS mapping after cert delete: {e}");
        }
    }

    async fn sync_api_dynamic_dns_redirects(&self) {
        let Some(dns_redirect_service) = self.api_dns_redirect_service.as_ref() else {
            return;
        };

        let certs = self.list().await;
        let batch = build_api_dynamic_dns_redirect_batch(&certs);
        let _ = dns_redirect_service.set_dynamic_batch(batch).await;
    }

    async fn check_auto_renewals(&self) {
        let certs = self.list().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as f64;

        for cert in certs {
            let acme = match &cert.cert_type {
                CertType::Acme(a) => a,
                _ => continue,
            };
            if !acme.auto_renew || !matches!(cert.status, CertStatus::Valid) {
                continue;
            }
            let Some(expires_at) = cert.expires_at else {
                continue;
            };
            let renew_threshold = expires_at - (acme.renew_before_days as f64 * 86400.0);
            if now >= renew_threshold {
                tracing::info!("Auto-renewing cert {}", cert.id);
                // Reset to Processing and enqueue
                let mut config = cert;
                config.status = CertStatus::Processing;
                config.status_message = None;
                let saved = self.set_and_notify(config).await;
                let svc = self.clone();
                let id = saved.id;
                tokio::spawn(async move {
                    if let Err(e) = svc.enqueue_issuance_task(id).await {
                        tracing::error!("Auto-renewal failed for cert {id}: {e}");
                    }
                });
            }
        }
    }

    /// Create or update a certificate. For Manual type with certificate present,
    /// parse the cert to extract domains/expiry/issued_at and set status to Valid.
    pub async fn create_or_update_cert(
        &self,
        mut config: CertConfig,
    ) -> Result<CertConfig, CertError> {
        let existing = self.find_by_id(config.id).await;

        if let Some(existing) = existing.as_ref() {
            if let (CertType::Acme(existing_acme), CertType::Acme(new_acme)) =
                (&existing.cert_type, &config.cert_type)
            {
                let has_valid_certificate = matches!(existing.status, CertStatus::Valid)
                    && existing.certificate.as_deref().is_some_and(|pem| !pem.trim().is_empty());

                if existing_acme.account_id != new_acme.account_id && has_valid_certificate {
                    return Err(CertError::AcmeAccountChangeRequiresRevocation);
                }
            }
        }

        match &config.cert_type {
            CertType::Generated(generated) => {
                config.domains = normalize_cert_domains(&config.domains);
                if config.domains.is_empty() {
                    return Err(CertError::InvalidStatusTransition(
                        "generated certificate requires at least one domain".to_string(),
                    ));
                }
                if generated.validity_days == 0 {
                    return Err(CertError::InvalidStatusTransition(
                        "generated certificate validity_days must be greater than zero".to_string(),
                    ));
                }

                let should_regenerate = existing.as_ref().is_none_or(|current| {
                    generated_cert_needs_regeneration(
                        current,
                        &config.domains,
                        generated.validity_days,
                    )
                });

                if should_regenerate {
                    let material =
                        generate_self_signed_certificate(&config.domains, generated.validity_days)?;
                    config.private_key = Some(material.private_key_pem);
                    config.certificate = Some(material.certificate_pem);
                    config.certificate_chain = None;
                    config.issued_at = Some(material.issued_at);
                    config.expires_at = Some(material.expires_at);
                    config.status = CertStatus::Valid;
                    config.status_message = None;
                } else if let Some(current) = existing.as_ref() {
                    config.private_key = current.private_key.clone();
                    config.certificate = current.certificate.clone();
                    config.certificate_chain = current.certificate_chain.clone();
                    config.issued_at = current.issued_at;
                    config.expires_at = current.expires_at;
                    config.status = CertStatus::Valid;
                    config.status_message = None;
                }
            }
            CertType::Manual => {
                let cert_pem_opt = config.certificate.as_deref().map(str::trim);
                let key_pem_opt = config.private_key.as_deref().map(str::trim);
                let has_cert = cert_pem_opt.is_some_and(|v| !v.is_empty());
                let has_key = key_pem_opt.is_some_and(|v| !v.is_empty());

                if has_cert != has_key {
                    return Err(CertError::InvalidStatusTransition(
                        "manual certificate and private key must be provided together".to_string(),
                    ));
                }

                if has_cert {
                    let cert_pem = cert_pem_opt.unwrap_or_default();
                    let key_pem = key_pem_opt.unwrap_or_default();
                    let (domains, not_before, not_after) = parse_cert_info(cert_pem)?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs_f64();

                    if now < not_before {
                        return Err(CertError::InvalidStatusTransition(
                            "manual certificate is not valid yet".to_string(),
                        ));
                    }
                    if now > not_after {
                        return Err(CertError::InvalidStatusTransition(
                            "manual certificate is expired".to_string(),
                        ));
                    }

                    validate_certified_key_from_pem(
                        cert_pem,
                        config.certificate_chain.as_deref(),
                        key_pem,
                    )
                    .map_err(|e| {
                        CertError::InvalidStatusTransition(format!(
                            "manual certificate/private key validation failed: {e}"
                        ))
                    })?;

                    if config.domains.is_empty() {
                        config.domains = domains;
                    }
                    config.expires_at = Some(not_after);
                    config.issued_at = Some(not_before);
                    config.status = CertStatus::Valid;
                }
            }
            CertType::Acme(acme) => {
                config.domains = normalize_cert_domains(&config.domains);
                if config.domains.is_empty() {
                    return Err(CertError::InvalidStatusTransition(
                        "ACME certificate requires at least one domain".to_string(),
                    ));
                }
                self.validate_acme_dns_access(acme, &config.domains).await?;
            }
        }

        self.validate_for_api_domain_conflicts(&config).await?;

        let saved = self.set_and_notify(config).await;
        Ok(saved)
    }

    async fn validate_for_api_domain_conflicts(
        &self,
        config: &CertConfig,
    ) -> Result<(), CertError> {
        if !config.for_api {
            return Ok(());
        }

        let normalized_domains: HashSet<String> = config
            .domains
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();

        if normalized_domains.is_empty() {
            return Ok(());
        }

        let certs = self.list().await;
        let mut conflicts: HashSet<String> = HashSet::new();
        for cert in certs {
            if cert.id == config.id || !cert.for_api {
                continue;
            }
            for domain in cert.domains {
                let candidate = domain.trim().to_ascii_lowercase();
                if normalized_domains.contains(&candidate) {
                    conflicts.insert(candidate);
                }
            }
        }

        if conflicts.is_empty() {
            return Ok(());
        }

        let mut conflict_list: Vec<String> = conflicts.into_iter().collect();
        conflict_list.sort_unstable();
        Err(CertError::InvalidStatusTransition(format!(
            "for_api domain conflict: {}",
            conflict_list.join(", ")
        )))
    }

    async fn resolve_dns_provider_profile(
        &self,
        provider_profile_id: Uuid,
    ) -> Result<DnsProviderProfile, CertError> {
        self.profile_store
            .find_by_id(provider_profile_id)
            .await
            .map_err(|e| CertError::DnsChallengeSetupFailed(e.to_string()))?
            .ok_or(CertError::DnsProviderProfileNotFound(provider_profile_id))
    }

    async fn validate_acme_dns_access(
        &self,
        acme: &AcmeCertConfig,
        domains: &[String],
    ) -> Result<(), CertError> {
        match &acme.challenge_type {
            ChallengeType::Dns { provider_profile_id } => {
                let profile = self.resolve_dns_provider_profile(*provider_profile_id).await?;
                dns_provider::build_solver(&profile.provider_config, profile.default_record_ttl())?;
                for domain in domains {
                    dns_provider::validate_provider_domain_access(&profile.provider_config, domain)
                        .await?;
                }
                Ok(())
            }
            ChallengeType::Http { .. } => Ok(()),
        }
    }

    async fn enqueue_issuance_task(&self, id: Uuid) -> Result<(), CertError> {
        let cancel = CancellationToken::new();
        {
            let mut tasks = self.tasks.lock().await;
            if tasks.contains_key(&id) {
                return Err(CertError::InvalidStatusTransition(
                    "issuance task is already running; cancel it first".to_string(),
                ));
            }
            tasks.insert(id, CertIssueTask { cancel: cancel.clone() });
        }

        let svc = self.clone();
        tokio::spawn(async move {
            if let Err(e) = svc.run_issue_task(id, cancel).await {
                tracing::error!("Issue task failed for cert {id}: {e}");
            }
        });
        Ok(())
    }

    pub async fn ensure_account_mutation_allowed(&self, account_id: Uuid) -> Result<(), CertError> {
        let certs = self.list().await;
        let mut blockers = Vec::new();

        for cert in certs {
            let CertType::Acme(acme) = &cert.cert_type else {
                continue;
            };
            if acme.account_id != account_id {
                continue;
            }

            if matches!(
                cert.status,
                CertStatus::Processing
                    | CertStatus::Ready
                    | CertStatus::Valid
                    | CertStatus::Expired
            ) {
                blockers.push(format!("{}({:?})", cert.id, cert.status));
            }
        }

        if blockers.is_empty() {
            return Ok(());
        }

        blockers.sort_unstable();
        Err(CertError::AccountHasActiveCertificates(blockers.join(", ")))
    }

    pub async fn sync_account_status_hint(&self, account_id: Uuid, account_status: &AccountStatus) {
        let tx_result = match self
            .store
            .sync_account_status_hint_tx(
                account_id,
                account_status,
                Self::ACCOUNT_STATUS_HINT_PREFIX,
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!("Failed to sync cert/account status hint in transaction: {e}");
                return;
            }
        };

        {
            let tasks = self.tasks.lock().await;
            for cert_id in &tx_result.cancelled_cert_ids {
                if let Some(task) = tasks.get(cert_id) {
                    task.cancel.cancel();
                }
            }
        }

        if !tx_result.changed_cert_ids.is_empty() && self.reload_api_tls_mapping().await.is_err() {
            tracing::warn!("Failed to reload API TLS mapping after account status sync");
        }
    }

    async fn run_issue_task(&self, id: Uuid, cancel: CancellationToken) -> Result<(), CertError> {
        let result = self.do_issue_cert(id, &cancel).await;
        let mut tasks = self.tasks.lock().await;
        tasks.remove(&id);
        result
    }

    /// Validate, set status to Processing, enqueue to background worker.
    /// Returns immediately with the Processing config.
    pub async fn issue_cert(&self, id: Uuid) -> Result<CertConfig, CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::CertNotFound(id))?;

        // Guard: must be ACME type
        match &config.cert_type {
            CertType::Acme(acme) => {
                self.validate_acme_dns_access(acme, &config.domains).await?;
            }
            _ => {
                return Err(CertError::InvalidStatusTransition(
                    "not an ACME certificate".to_string(),
                ))
            }
        };

        // Status guard
        match config.status {
            CertStatus::Pending
            | CertStatus::Invalid
            | CertStatus::Expired
            | CertStatus::Revoked
            | CertStatus::Cancelled => {}
            ref s => {
                return Err(CertError::InvalidStatusTransition(format!("{s:?}")));
            }
        }

        // Set to Processing and return immediately
        config.status = CertStatus::Processing;
        config.status_message = None;
        let saved = self.set_and_notify(config).await;

        self.enqueue_issuance_task(id).await?;

        Ok(saved)
    }

    pub async fn cancel_cert(&self, id: Uuid) -> Result<CertConfig, CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::CertNotFound(id))?;
        match &config.cert_type {
            CertType::Acme(_) => {}
            _ => {
                return Err(CertError::InvalidStatusTransition(
                    "not an ACME certificate".to_string(),
                ));
            }
        }
        if !matches!(config.status, CertStatus::Processing) {
            return Err(CertError::InvalidStatusTransition(format!("{:?}", config.status)));
        }

        {
            let tasks = self.tasks.lock().await;
            if let Some(task) = tasks.get(&id) {
                task.cancel.cancel();
            }
        }

        config.status = CertStatus::Cancelled;
        config.status_message = Some("cancelled by user".to_string());
        let saved = self.set_and_notify(config).await;
        Ok(saved)
    }

    /// The actual ACME issuance logic (runs in background worker).
    async fn do_issue_cert(&self, id: Uuid, cancel: &CancellationToken) -> Result<(), CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::CertNotFound(id))?;

        let acme = match &config.cert_type {
            CertType::Acme(a) => a.clone(),
            _ => return Ok(()),
        };

        let result = async {
            if cancel.is_cancelled() {
                return Ok(DoIssueResult::Cancelled);
            }
            let solver = match acme.challenge_type {
                ChallengeType::Dns { provider_profile_id } => {
                    let profile = self.resolve_dns_provider_profile(provider_profile_id).await?;
                    dns_provider::build_solver(
                        &profile.provider_config,
                        profile.default_record_ttl(),
                    )?
                }
                ChallengeType::Http { .. } => {
                    return Err(CertError::DnsChallengeSetupFailed(
                        "only DNS-01 challenge is supported".to_string(),
                    ));
                }
            };

            let account_config = self
                .account_service
                .find_by_id(acme.account_id)
                .await
                .ok_or(CertError::AccountNotFound(acme.account_id))?;

            if !matches!(account_config.status, AccountStatus::Registered) {
                return Err(CertError::IssuanceFailed(format!(
                    "ACME account is not registered: {:?}",
                    account_config.status
                )));
            }

            let verified_account = self.account_service.verify_account(acme.account_id).await?;

            if !matches!(verified_account.status, AccountStatus::Registered) {
                return Err(CertError::IssuanceFailed(format!(
                    "ACME account verification failed, current status: {:?}",
                    verified_account.status
                )));
            }

            let credentials_json =
                verified_account.account_private_key.as_ref().ok_or_else(|| {
                    CertError::IssuanceFailed("Account has no credentials".to_string())
                })?;

            let mut dns_records: Vec<(String, String)> = Vec::new();
            let issue_result = self
                .do_issue(credentials_json, &config, solver.as_ref(), cancel, &mut dns_records)
                .await;

            for (domain, value) in &dns_records {
                if let Err(e) = solver.cleanup_txt_record(domain, value).await {
                    tracing::warn!("Failed to clean up DNS record for {domain}: {e}");
                }
            }
            issue_result
        }
        .await;

        match result {
            Ok(DoIssueResult::Issued { private_key_pem, cert_chain_pem, expires_at }) => {
                let (certificate, certificate_chain) = split_cert_chain(&cert_chain_pem);

                config.status = CertStatus::Valid;
                config.status_message = None;
                config.private_key = Some(private_key_pem);
                config.certificate = Some(certificate);
                config.certificate_chain =
                    if certificate_chain.is_empty() { None } else { Some(certificate_chain) };
                config.expires_at = Some(expires_at);
                config.issued_at = Some(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as f64,
                );
            }
            Ok(DoIssueResult::Cancelled) => {
                config.status = CertStatus::Cancelled;
                config.status_message = Some("cancelled by user".to_string());
            }
            Err(e) => {
                config.status = CertStatus::Invalid;
                config.status_message = Some(e.to_string());
                tracing::error!("Certificate issuance failed for cert {id}: {e}");
            }
        }

        self.set_and_notify(config).await;
        Ok(())
    }

    async fn do_issue(
        &self,
        credentials_json: &str,
        config: &CertConfig,
        solver: &dyn dns_provider::DnsChallengeSolver,
        cancel: &CancellationToken,
        dns_records: &mut Vec<(String, String)>,
    ) -> Result<DoIssueResult, CertError> {
        if cancel.is_cancelled() {
            return Ok(DoIssueResult::Cancelled);
        }
        let credentials: instant_acme::AccountCredentials = serde_json::from_str(credentials_json)
            .map_err(|e| {
                CertError::IssuanceFailed(format!("Failed to parse account credentials: {e}"))
            })?;

        let account = Account::builder()
            .map_err(|e| CertError::IssuanceFailed(e.to_string()))?
            .from_credentials(credentials)
            .await
            .map_err(|e| CertError::IssuanceFailed(e.to_string()))?;

        // Build identifiers
        let identifiers: Vec<Identifier> =
            config.domains.iter().map(|d| Identifier::Dns(d.clone())).collect();

        // Create order
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| CertError::IssuanceFailed(format!("Failed to create ACME order: {e}")))?;

        // Phase 1: create all DNS TXT records
        {
            let mut authz_stream = order.authorizations();
            while let Some(result) = authz_stream.next().await {
                let mut authz = result.map_err(|e| {
                    CertError::IssuanceFailed(format!("Failed to get authorization: {e}"))
                })?;

                let challenge = authz.challenge(AcmeChallengeType::Dns01).ok_or_else(|| {
                    CertError::DnsChallengeSetupFailed(
                        "No DNS-01 challenge available for authorization".to_string(),
                    )
                })?;

                // For wildcard certs, DNS-01 record goes on the base domain (RFC 8555 §8.4)
                let raw_domain = challenge.identifier().to_string();
                let domain = raw_domain.strip_prefix("*.").unwrap_or(&raw_domain).to_string();
                let dns_value = challenge.key_authorization().dns_value();

                tokio::select! {
                    _ = cancel.cancelled() => return Ok(DoIssueResult::Cancelled),
                    create_result = solver.create_txt_record(&domain, &dns_value) => {
                        create_result?;
                    }
                }
                dns_records.push((domain.clone(), dns_value.clone()));
            }
        }

        // Wait for DNS propagation before notifying ACME server
        tracing::info!("Waiting 45s for DNS propagation...");
        if cancellable_sleep(cancel, Duration::from_secs(45)).await {
            return Ok(DoIssueResult::Cancelled);
        }

        // Phase 2: notify ACME server that challenges are ready
        {
            let mut authz_stream = order.authorizations();
            while let Some(result) = authz_stream.next().await {
                let mut authz = result.map_err(|e| {
                    CertError::IssuanceFailed(format!("Failed to get authorization: {e}"))
                })?;

                let mut challenge = authz.challenge(AcmeChallengeType::Dns01).ok_or_else(|| {
                    CertError::DnsChallengeSetupFailed(
                        "No DNS-01 challenge available for authorization".to_string(),
                    )
                })?;

                tokio::select! {
                    _ = cancel.cancelled() => return Ok(DoIssueResult::Cancelled),
                    ready_result = challenge.set_ready() => {
                        ready_result.map_err(|e| {
                            CertError::IssuanceFailed(format!("Challenge set_ready failed: {e}"))
                        })?;
                    }
                }

                // Brief delay between set_ready calls to avoid API rate limits
                if cancellable_sleep(cancel, Duration::from_secs(1)).await {
                    return Ok(DoIssueResult::Cancelled);
                }
            }
        }

        // Wait briefly for ACME server to start validating
        if cancellable_sleep(cancel, Duration::from_secs(10)).await {
            return Ok(DoIssueResult::Cancelled);
        }

        // Wait for order to become Ready (or Invalid)
        let retry_policy = RetryPolicy::new()
            .initial_delay(Duration::from_secs(5))
            .timeout(Duration::from_secs(300));

        let order_status = tokio::select! {
            _ = cancel.cancelled() => return Ok(DoIssueResult::Cancelled),
            status = order.poll_ready(&retry_policy) => status
        }
        .map_err(|e| CertError::IssuanceFailed(format!("Order poll_ready failed: {e}")))?;

        if order_status != OrderStatus::Ready {
            return Err(CertError::IssuanceFailed(format!(
                "Order validation failed, status: {order_status:?}"
            )));
        }

        // Finalize: auto-generates CSR, returns private key PEM
        let private_key_pem = tokio::select! {
            _ = cancel.cancelled() => return Ok(DoIssueResult::Cancelled),
            key = order.finalize() => key
        }
        .map_err(|e| CertError::IssuanceFailed(format!("Order finalize failed: {e}")))?;

        // Get certificate chain PEM
        let cert_chain_pem = tokio::select! {
            _ = cancel.cancelled() => return Ok(DoIssueResult::Cancelled),
            chain = order.poll_certificate(&retry_policy) => chain
        }
        .map_err(|e| CertError::IssuanceFailed(format!("Order poll_certificate failed: {e}")))?;

        // Parse certificate to extract expiry (not_after)
        let expires_at = parse_cert_expiry(&cert_chain_pem)?;

        Ok(DoIssueResult::Issued { private_key_pem, cert_chain_pem, expires_at })
    }

    pub async fn revoke_cert(&self, id: Uuid) -> Result<CertConfig, CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::CertNotFound(id))?;

        // Guard: must be ACME type
        let acme = match &config.cert_type {
            CertType::Acme(a) => a.clone(),
            _ => {
                return Err(CertError::InvalidStatusTransition(
                    "not an ACME certificate".to_string(),
                ))
            }
        };

        // Status guard: only Valid allowed
        if !matches!(config.status, CertStatus::Valid) {
            return Err(CertError::InvalidStatusTransition(format!("{:?}", config.status)));
        }

        let cert_pem = config
            .certificate
            .as_ref()
            .ok_or_else(|| CertError::RevocationFailed("No certificate to revoke".to_string()))?;

        let account_config = self
            .account_service
            .find_by_id(acme.account_id)
            .await
            .ok_or(CertError::AccountNotFound(acme.account_id))?;

        let credentials_json = account_config
            .account_private_key
            .as_ref()
            .ok_or_else(|| CertError::RevocationFailed("Account has no credentials".to_string()))?;

        // Parse PEM to DER
        let cert_der = pem_to_der(cert_pem)?;

        let credentials: instant_acme::AccountCredentials = serde_json::from_str(credentials_json)
            .map_err(|e| {
                CertError::RevocationFailed(format!("Failed to parse account credentials: {e}"))
            })?;

        let account = Account::builder()
            .map_err(|e| CertError::RevocationFailed(e.to_string()))?
            .from_credentials(credentials)
            .await
            .map_err(|e| CertError::RevocationFailed(e.to_string()))?;

        let cert_der_ref = CertificateDer::from(cert_der.as_slice());
        match account.revoke(&RevocationRequest { certificate: &cert_der_ref, reason: None }).await
        {
            Ok(()) => {
                config.status = CertStatus::Revoked;
                config.private_key = None;
                config.certificate = None;
                config.certificate_chain = None;
                config.status_message = None;
                tracing::info!("Certificate revoked for cert {id}");
            }
            Err(e) => {
                config.status_message = Some(e.to_string());
                tracing::error!("Certificate revocation failed for cert {id}: {e}");
                return Err(CertError::RevocationFailed(e.to_string()));
            }
        }

        let saved = self.set_and_notify(config).await;
        Ok(saved)
    }

    /// Validate, set Processing, enqueue to background worker.
    /// Returns immediately with the Processing config.
    pub async fn renew_cert(&self, id: Uuid) -> Result<CertConfig, CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::CertNotFound(id))?;

        // Guard: must be ACME type
        match &config.cert_type {
            CertType::Acme(_) => {}
            _ => {
                return Err(CertError::InvalidStatusTransition(
                    "not an ACME certificate".to_string(),
                ))
            }
        };

        // Status guard: only Valid or Expired allowed
        match config.status {
            CertStatus::Valid | CertStatus::Expired => {}
            ref s => {
                return Err(CertError::InvalidStatusTransition(format!("{s:?}")));
            }
        }

        // Set to Processing, keep current cert data until renewal succeeds
        config.status = CertStatus::Processing;
        config.status_message = None;
        let saved = self.set_and_notify(config).await;

        self.enqueue_issuance_task(id).await?;

        Ok(saved)
    }

    pub async fn get_cert_info(&self, id: Uuid) -> Result<CertParsedInfo, CertError> {
        let config = self.find_by_id(id).await.ok_or(CertError::CertNotFound(id))?;
        let cert_pem = config
            .certificate
            .as_ref()
            .ok_or_else(|| CertError::IssuanceFailed("No certificate content".to_string()))?;
        parse_cert_details(cert_pem)
    }
}

fn build_api_dynamic_dns_redirect_batch(certs: &[CertConfig]) -> DynamicDnsRedirectBatch {
    let mut matches = HashSet::new();
    for cert in certs.iter().filter(|cert| cert.for_api) {
        for domain in &cert.domains {
            if let Some(domain_match) = cert_domain_to_dynamic_match(domain) {
                matches.insert(domain_match);
            }
        }
    }

    let mut records: Vec<_> = matches.into_iter().collect();
    records.sort_by(|left, right| dynamic_match_sort_key(left).cmp(&dynamic_match_sort_key(right)));

    DynamicDnsRedirectBatch {
        source_id: API_CERT_DYNAMIC_DNS_REDIRECT_SOURCE_ID.to_string(),
        scope: DynamicDnsRedirectScope::Global,
        records: records
            .into_iter()
            .map(|match_rule| DynamicDnsRedirectRecord {
                match_rule,
                answer_mode: DnsRedirectAnswerMode::AllLocalIps,
                result_info: vec![],
                ttl_secs: DEFAULT_STATIC_DNS_REDIRECT_TTL_SECS,
                block_metadata_queries: DEFAULT_BLOCK_METADATA_QUERIES,
            })
            .collect(),
    }
}

fn cert_domain_to_dynamic_match(domain: &str) -> Option<DynamicDnsMatch> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    if let Some(suffix) = normalized.strip_prefix("*.") {
        if suffix.is_empty() {
            None
        } else {
            Some(DynamicDnsMatch::Domain(suffix.to_string()))
        }
    } else {
        Some(DynamicDnsMatch::Full(normalized))
    }
}

fn dynamic_match_sort_key(value: &DynamicDnsMatch) -> (u8, &str) {
    match value {
        DynamicDnsMatch::Full(value) => (0, value.as_str()),
        DynamicDnsMatch::Domain(value) => (1, value.as_str()),
    }
}

#[async_trait::async_trait]
impl ConfigController for CertService {
    type Id = Uuid;
    type Config = CertConfig;
    type DatabseAction = CertRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

fn normalize_cert_domains(domains: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for domain in domains {
        let domain = domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            continue;
        }
        if seen.insert(domain.clone()) {
            normalized.push(domain);
        }
    }

    normalized
}

fn generated_cert_needs_regeneration(
    current: &CertConfig,
    normalized_domains: &[String],
    validity_days: u32,
) -> bool {
    let CertType::Generated(current_generated) = &current.cert_type else {
        return true;
    };

    current_generated.validity_days != validity_days
        || normalize_cert_domains(&current.domains) != normalized_domains
        || !matches!(current.status, CertStatus::Valid)
        || current.certificate.as_deref().is_none_or(|pem| pem.trim().is_empty())
        || current.private_key.as_deref().is_none_or(|pem| pem.trim().is_empty())
}

fn generate_self_signed_certificate(
    domains: &[String],
    validity_days: u32,
) -> Result<GeneratedCertMaterial, CertError> {
    let start_date = Utc::now().date_naive();
    let end_date = start_date
        .checked_add_signed(ChronoDuration::days(validity_days as i64 + 1))
        .ok_or_else(|| {
            CertError::InvalidStatusTransition(
                "generated certificate validity is out of supported range".to_string(),
            )
        })?;

    let mut params = CertificateParams::new(domains.to_vec()).map_err(|e| {
        CertError::InvalidStatusTransition(format!(
            "generated certificate domain validation failed: {e}"
        ))
    })?;
    let not_before = date_time_ymd(
        start_date.year(),
        start_date.month().try_into().map_err(|_| {
            CertError::IssuanceFailed("failed to calculate generated cert start month".to_string())
        })?,
        start_date.day().try_into().map_err(|_| {
            CertError::IssuanceFailed("failed to calculate generated cert start day".to_string())
        })?,
    );
    let not_after = date_time_ymd(
        end_date.year(),
        end_date.month().try_into().map_err(|_| {
            CertError::IssuanceFailed("failed to calculate generated cert end month".to_string())
        })?,
        end_date.day().try_into().map_err(|_| {
            CertError::IssuanceFailed("failed to calculate generated cert end day".to_string())
        })?,
    );
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, domains[0].clone());
    params.distinguished_name = distinguished_name;
    params.not_before = not_before;
    params.not_after = not_after;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let signing_key = KeyPair::generate().map_err(|e| {
        CertError::IssuanceFailed(format!("failed to generate private key for certificate: {e}"))
    })?;
    let certificate = params.self_signed(&signing_key).map_err(|e| {
        CertError::IssuanceFailed(format!("failed to generate self-signed certificate: {e}"))
    })?;

    Ok(GeneratedCertMaterial {
        private_key_pem: signing_key.serialize_pem(),
        certificate_pem: certificate.pem(),
        issued_at: not_before.unix_timestamp() as f64,
        expires_at: not_after.unix_timestamp() as f64,
    })
}

/// Split a PEM certificate chain into the leaf certificate and the rest of the chain
fn split_cert_chain(pem_chain: &str) -> (String, String) {
    let marker = "-----END CERTIFICATE-----";
    if let Some(pos) = pem_chain.find(marker) {
        let end = pos + marker.len();
        let cert = pem_chain[..end].trim().to_string();
        let chain = pem_chain[end..].trim().to_string();
        (cert, chain)
    } else {
        (pem_chain.to_string(), String::new())
    }
}

/// Parse PEM certificate to extract the not_after timestamp as Unix seconds
fn parse_cert_expiry(pem_chain: &str) -> Result<f64, CertError> {
    let pem_obj = pem::parse(pem_chain)
        .map_err(|e| CertError::IssuanceFailed(format!("Failed to parse certificate PEM: {e}")))?;

    let (_, cert) = x509_parser::parse_x509_certificate(pem_obj.contents()).map_err(|e| {
        CertError::IssuanceFailed(format!("Failed to parse X.509 certificate: {e}"))
    })?;

    let not_after = cert.validity().not_after.timestamp();
    Ok(not_after as f64)
}

/// Parse PEM certificate to extract domains (SANs), not_before, not_after
fn parse_cert_info(pem_str: &str) -> Result<(Vec<String>, f64, f64), CertError> {
    let pem_obj = pem::parse(pem_str)
        .map_err(|e| CertError::IssuanceFailed(format!("Failed to parse certificate PEM: {e}")))?;

    let (_, cert) = x509_parser::parse_x509_certificate(pem_obj.contents()).map_err(|e| {
        CertError::IssuanceFailed(format!("Failed to parse X.509 certificate: {e}"))
    })?;

    let not_before = cert.validity().not_before.timestamp() as f64;
    let not_after = cert.validity().not_after.timestamp() as f64;
    let domains = extract_cert_dns_names_from_pem(pem_str).map_err(|e| {
        CertError::IssuanceFailed(format!("Failed to extract certificate DNS names: {e}"))
    })?;

    Ok((domains, not_before, not_after))
}

fn parse_cert_details(pem_str: &str) -> Result<CertParsedInfo, CertError> {
    let pem_obj = pem::parse(pem_str)
        .map_err(|e| CertError::IssuanceFailed(format!("Failed to parse certificate PEM: {e}")))?;

    let der = pem_obj.contents();
    let (_, cert) = x509_parser::parse_x509_certificate(der).map_err(|e| {
        CertError::IssuanceFailed(format!("Failed to parse X.509 certificate: {e}"))
    })?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let serial_number = hex_string(cert.tbs_certificate.raw_serial());
    let signature_algorithm = format!("{:?}", cert.signature_algorithm.algorithm);
    let not_before = cert.validity().not_before.timestamp() as f64;
    let not_after = cert.validity().not_after.timestamp() as f64;

    let mut subject_alt_names = Vec::new();
    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    subject_alt_names.push(dns.to_string());
                }
            }
        }
    }

    if subject_alt_names.is_empty() {
        if let Some(cn) = cert.subject().iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                subject_alt_names.push(cn_str.to_string());
            }
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(der);
    let fingerprint_sha256 = hex_string(&hasher.finalize());

    Ok(CertParsedInfo {
        subject,
        issuer,
        serial_number,
        subject_alt_names,
        signature_algorithm,
        not_before,
        not_after,
        fingerprint_sha256,
    })
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":")
}

async fn cancellable_sleep(cancel: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

/// Convert PEM-encoded certificate to DER bytes
fn pem_to_der(pem_str: &str) -> Result<Vec<u8>, CertError> {
    let pem_obj = pem::parse(pem_str).map_err(|e| {
        CertError::RevocationFailed(format!("Failed to parse certificate PEM: {e}"))
    })?;
    Ok(pem_obj.into_contents())
}

#[cfg(test)]
mod tests {
    use super::*;
    use landscape_common::cert::order::GeneratedCertConfig;

    #[test]
    fn generated_certificate_uses_requested_domains_and_validity() {
        let domains = vec!["example.com".to_string(), "www.example.com".to_string()];
        let material =
            generate_self_signed_certificate(&domains, 30).expect("generated cert should succeed");
        let (mut parsed_domains, not_before, not_after) =
            parse_cert_info(&material.certificate_pem).expect("generated cert should parse");
        let mut expected_domains = domains.clone();

        parsed_domains.sort();
        expected_domains.sort();

        assert_eq!(parsed_domains, expected_domains);
        assert!(material.private_key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(material.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(not_after > not_before);
        assert!(not_after - not_before >= 30.0 * 86400.0 - 1.0);
    }

    #[test]
    fn build_api_dynamic_dns_redirect_batch_only_includes_for_api_domains() {
        let batch = build_api_dynamic_dns_redirect_batch(&[
            CertConfig {
                id: Uuid::new_v4(),
                name: "api".to_string(),
                domains: vec!["api.example.com".to_string()],
                status: CertStatus::Pending,
                private_key: None,
                certificate: None,
                certificate_chain: None,
                expires_at: None,
                issued_at: None,
                status_message: None,
                cert_type: CertType::Generated(GeneratedCertConfig { validity_days: 30 }),
                for_api: true,
                for_gateway: false,
                update_at: 0.0,
            },
            CertConfig {
                id: Uuid::new_v4(),
                name: "gateway".to_string(),
                domains: vec!["gw.example.com".to_string()],
                status: CertStatus::Valid,
                private_key: None,
                certificate: None,
                certificate_chain: None,
                expires_at: None,
                issued_at: None,
                status_message: None,
                cert_type: CertType::Manual,
                for_api: false,
                for_gateway: true,
                update_at: 0.0,
            },
        ]);

        assert_eq!(batch.source_id, API_CERT_DYNAMIC_DNS_REDIRECT_SOURCE_ID);
        assert_eq!(batch.scope, DynamicDnsRedirectScope::Global);
        assert_eq!(batch.records.len(), 1);
        assert_eq!(
            batch.records[0].match_rule,
            DynamicDnsMatch::Full("api.example.com".to_string())
        );
        assert_eq!(batch.records[0].answer_mode, DnsRedirectAnswerMode::AllLocalIps);
        assert!(batch.records[0].result_info.is_empty());
    }

    #[test]
    fn wildcard_cert_domain_maps_to_domain_match() {
        assert_eq!(
            cert_domain_to_dynamic_match("*.example.com"),
            Some(DynamicDnsMatch::Domain("example.com".to_string()))
        );
        assert_eq!(
            cert_domain_to_dynamic_match(" Api.Example.Com. "),
            Some(DynamicDnsMatch::Full("api.example.com".to_string()))
        );
    }
}
