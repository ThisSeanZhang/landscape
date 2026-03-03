use base64::Engine;
use instant_acme::{Account, ExternalAccountKey, LetsEncrypt, NewAccount, ZeroSsl};
use landscape_common::cert::account::{AccountStatus, CertAccountConfig, ProviderConfig};
use landscape_common::cert::CertError;
use landscape_common::service::controller::ConfigController;
use landscape_database::cert_account::repository::CertAccountRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use tracing;
use uuid::Uuid;

/// Check if an instant-acme error indicates the account does not exist on the server
fn is_account_not_exist_error(err: &instant_acme::Error) -> bool {
    if let instant_acme::Error::Api(problem) = err {
        if let Some(ref t) = problem.r#type {
            return t == "urn:ietf:params:acme:error:accountDoesNotExist";
        }
    }
    false
}

#[derive(Clone)]
pub struct CertAccountService {
    store: CertAccountRepository,
}

impl CertAccountService {
    pub async fn new(store_provider: LandscapeDBServiceProvider) -> Self {
        let store = store_provider.cert_account_store();
        let service = Self { store };

        // Startup cleanup: reset any accounts stuck in Registering back to Unregistered
        let accounts = service.list().await;
        for mut account in accounts {
            if matches!(account.status, AccountStatus::Registering) {
                tracing::warn!(
                    "Account {} was stuck in Registering status, resetting to Unregistered",
                    account.id
                );
                account.status = AccountStatus::Unregistered;
                account.status_message = None;
                let _ = service.set(account).await;
            }
        }

        service
    }

    pub async fn register_account(&self, id: Uuid) -> Result<CertAccountConfig, CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::AccountNotFound(id))?;

        // Only allow registration from Unregistered or Error
        match config.status {
            AccountStatus::Unregistered | AccountStatus::Error => {}
            ref s => {
                return Err(CertError::InvalidStatusTransition(format!("{s:?}")));
            }
        }

        // ZeroSSL does not support staging
        if matches!(config.provider_config, ProviderConfig::ZeroSsl { .. }) && config.use_staging {
            return Err(CertError::StagingNotSupported);
        }

        // Set status to Registering
        config.status = AccountStatus::Registering;
        config.status_message = None;
        let _ = self.set(config.clone()).await;

        // Determine directory URL
        let directory_url = match &config.provider_config {
            ProviderConfig::LetsEncrypt => {
                if config.use_staging {
                    LetsEncrypt::Staging.url()
                } else {
                    LetsEncrypt::Production.url()
                }
            }
            ProviderConfig::ZeroSsl { .. } => ZeroSsl::Production.url(),
        };

        // Build EAB if ZeroSSL
        let eab = match &config.provider_config {
            ProviderConfig::ZeroSsl { eab_kid, eab_hmac_key } => {
                let hmac_bytes =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(eab_hmac_key).map_err(
                        |e| CertError::RegistrationFailed(format!("Invalid EAB HMAC key: {e}")),
                    )?;
                Some(ExternalAccountKey::new(eab_kid.clone(), &hmac_bytes))
            }
            _ => None,
        };

        let contact = [format!("mailto:{}", config.email)];
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

        let result = Account::builder()
            .map_err(|e| CertError::RegistrationFailed(e.to_string()))?
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: config.terms_agreed,
                    only_return_existing: false,
                },
                directory_url.to_string(),
                eab.as_ref(),
            )
            .await;

        match result {
            Ok((account, credentials)) => {
                config.status = AccountStatus::Registered;
                config.status_message = None;
                config.account_private_key =
                    Some(serde_json::to_string(&credentials).map_err(|e| {
                        CertError::RegistrationFailed(format!(
                            "Failed to serialize credentials: {e}"
                        ))
                    })?);
                config.acme_account_url = Some(account.id().to_owned());
                tracing::info!("ACME account registered: {}", id);
            }
            Err(e) => {
                config.status = AccountStatus::Error;
                config.status_message = Some(e.to_string());
                tracing::error!("ACME registration failed for {}: {}", id, e);
            }
        }

        let saved = self.set(config).await;
        Ok(saved)
    }

    pub async fn verify_account(&self, id: Uuid) -> Result<CertAccountConfig, CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::AccountNotFound(id))?;

        // Only allow verification when Registered
        if !matches!(config.status, AccountStatus::Registered) {
            return Err(CertError::InvalidStatusTransition(format!("{:?}", config.status)));
        }

        let credentials_str = config
            .account_private_key
            .as_ref()
            .ok_or_else(|| CertError::VerificationFailed("No credentials stored".to_string()))?;

        let credentials: instant_acme::AccountCredentials = serde_json::from_str(credentials_str)
            .map_err(|e| {
            CertError::VerificationFailed(format!("Failed to parse credentials: {e}"))
        })?;

        let verify_result = async {
            let account = Account::builder()
                .map_err(|e| instant_acme::Error::Other(e.to_string().into()))?
                .from_credentials(credentials)
                .await?;
            let contact = format!("mailto:{}", config.email);
            account.update_contacts(&[&contact]).await
        }
        .await;

        match verify_result {
            Ok(()) => {
                config.status = AccountStatus::Registered;
                config.status_message = None;
                tracing::info!("ACME account {} verified successfully", id);
            }
            Err(ref e) if is_account_not_exist_error(e) => {
                config.status = AccountStatus::Unregistered;
                config.status_message = None;
                config.account_private_key = None;
                config.acme_account_url = None;
                tracing::warn!("ACME account {} no longer exists on server", id);
            }
            Err(e) => {
                config.status = AccountStatus::Error;
                config.status_message = Some(e.to_string());
                tracing::error!("ACME account {} verification failed: {}", id, e);
            }
        }

        let saved = self.set(config).await;
        Ok(saved)
    }

    pub async fn deactivate_account(&self, id: Uuid) -> Result<CertAccountConfig, CertError> {
        let mut config = self.find_by_id(id).await.ok_or(CertError::AccountNotFound(id))?;

        // Only allow deactivation when Registered
        if !matches!(config.status, AccountStatus::Registered) {
            return Err(CertError::InvalidStatusTransition(format!("{:?}", config.status)));
        }

        let credentials_str = config
            .account_private_key
            .as_ref()
            .ok_or_else(|| CertError::DeactivationFailed("No credentials stored".to_string()))?;

        let credentials: instant_acme::AccountCredentials = serde_json::from_str(credentials_str)
            .map_err(|e| {
            CertError::DeactivationFailed(format!("Failed to parse credentials: {e}"))
        })?;

        let deactivate_result = async {
            let account = Account::builder()
                .map_err(|e| instant_acme::Error::Other(e.to_string().into()))?
                .from_credentials(credentials)
                .await?;
            account.deactivate().await
        }
        .await;

        match deactivate_result {
            Ok(()) => {
                config.status = AccountStatus::Unregistered;
                config.status_message = None;
                config.account_private_key = None;
                config.acme_account_url = None;
                tracing::info!("ACME account deactivated: {}", id);
            }
            Err(ref e) if is_account_not_exist_error(e) => {
                // Account already gone on server — clean up locally
                config.status = AccountStatus::Unregistered;
                config.status_message = None;
                config.account_private_key = None;
                config.acme_account_url = None;
                tracing::warn!("ACME account {} not found on server, cleaning up locally", id);
            }
            Err(e) => {
                config.status = AccountStatus::Error;
                config.status_message = Some(e.to_string());
                tracing::error!("ACME deactivation failed for {}: {}", id, e);
            }
        }

        let saved = self.set(config).await;
        Ok(saved)
    }
}

#[async_trait::async_trait]
impl ConfigController for CertAccountService {
    type Id = Uuid;
    type Config = CertAccountConfig;
    type DatabseAction = CertAccountRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}
