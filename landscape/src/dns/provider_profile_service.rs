use landscape_common::{
    cert::order::{CertType, ChallengeType, DnsProviderConfig},
    database::LandscapeStore,
    dns::provider_profile::{
        DnsProviderCredentialCheckRequest, DnsProviderCredentialCheckResult, DnsProviderProfile,
        DnsProviderProfileError,
    },
    service::controller::ConfigController,
};
use landscape_database::{
    cert::repository::CertRepository, ddns::repository::DdnsJobRepository,
    dns_provider_profile::repository::DnsProviderProfileRepository,
    provider::LandscapeDBServiceProvider,
};
use uuid::Uuid;

use crate::cert::dns_provider;

#[derive(Clone)]
pub struct DnsProviderProfileService {
    store: DnsProviderProfileRepository,
    ddns_store: DdnsJobRepository,
    cert_store: CertRepository,
}

impl DnsProviderProfileService {
    pub async fn new(store: LandscapeDBServiceProvider) -> Self {
        Self {
            store: store.dns_provider_profile_store(),
            ddns_store: store.ddns_job_store(),
            cert_store: store.cert_store(),
        }
    }

    pub async fn checked_set_profile(
        &self,
        config: DnsProviderProfile,
    ) -> Result<DnsProviderProfile, DnsProviderProfileError> {
        config.validate().map_err(DnsProviderProfileError::Invalid)?;
        if matches!(config.provider_config, DnsProviderConfig::Manual) {
            return Err(DnsProviderProfileError::ManualNotAllowed);
        }
        if let Some(existing) = self.store.find_by_name(&config.name).await?
            && existing.id != config.id
        {
            return Err(DnsProviderProfileError::NameConflict(config.name.clone()));
        }
        Ok(self.checked_set(config).await?)
    }

    pub async fn validate_credentials(
        &self,
        request: DnsProviderCredentialCheckRequest,
    ) -> Result<DnsProviderCredentialCheckResult, DnsProviderProfileError> {
        if matches!(&request.provider_config, DnsProviderConfig::Manual) {
            return Err(DnsProviderProfileError::ManualNotAllowed);
        }

        dns_provider::validate_provider_credentials(&request.provider_config)
            .await
            .map_err(|e| DnsProviderProfileError::CredentialError(e.to_string()))?;

        Ok(DnsProviderCredentialCheckResult {
            message: "DNS provider credentials validated successfully".to_string(),
        })
    }

    pub async fn delete_profile(&self, id: Uuid) -> Result<(), DnsProviderProfileError> {
        let ddns_refs: Vec<String> = self
            .ddns_store
            .list()
            .await?
            .into_iter()
            .filter(|job| job.provider_profile_id == id)
            .map(|job| job.name)
            .collect();
        if !ddns_refs.is_empty() {
            return Err(DnsProviderProfileError::InUseByDdns(ddns_refs.join(", ")));
        }

        let cert_refs: Vec<String> = self
            .cert_store
            .list()
            .await?
            .into_iter()
            .filter(|cert| {
                matches!(
                    &cert.cert_type,
                    CertType::Acme(acme)
                        if matches!(
                            &acme.challenge_type,
                            ChallengeType::Dns { provider_profile_id } if *provider_profile_id == id
                        )
                )
            })
            .map(|cert| cert.name)
            .collect();
        if !cert_refs.is_empty() {
            return Err(DnsProviderProfileError::InUseByCerts(cert_refs.join(", ")));
        }

        self.delete(id).await;
        Ok(())
    }
}

#[async_trait::async_trait]
impl ConfigController for DnsProviderProfileService {
    type Id = Uuid;
    type Config = DnsProviderProfile;
    type DatabseAction = DnsProviderProfileRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}
