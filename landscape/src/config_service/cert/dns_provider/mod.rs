mod cloudflare;

use landscape_common::cert::order::{ChallengeType, DnsProviderConfig};
use landscape_common::cert::CertError;

#[async_trait::async_trait]
pub trait DnsChallengeSolver: Send + Sync {
    /// Create a TXT record: _acme-challenge.{domain} → value
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError>;
    /// Remove the TXT record after validation
    async fn cleanup_txt_record(&self, domain: &str, value: &str) -> Result<(), CertError>;
}

/// Factory: build solver from order's challenge_type config
pub fn build_solver(
    challenge_type: &ChallengeType,
) -> Result<Box<dyn DnsChallengeSolver>, CertError> {
    match challenge_type {
        ChallengeType::Dns { dns_provider } => match dns_provider {
            DnsProviderConfig::Cloudflare { api_token } => {
                Ok(Box::new(cloudflare::CloudflareSolver::new(api_token.clone())))
            }
            DnsProviderConfig::Manual => Err(CertError::DnsChallengeSetupFailed(
                "manual DNS not supported for async issuance".into(),
            )),
            _ => Err(CertError::DnsChallengeSetupFailed("provider not yet implemented".into())),
        },
        ChallengeType::Http { .. } => {
            Err(CertError::DnsChallengeSetupFailed("only DNS-01 challenge is supported".into()))
        }
    }
}
