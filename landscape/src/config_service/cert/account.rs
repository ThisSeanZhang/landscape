use landscape_common::cert::account::CertAccountConfig;
use landscape_common::service::controller::ConfigController;
use landscape_database::cert_account::repository::CertAccountRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use uuid::Uuid;

#[derive(Clone)]
pub struct CertAccountService {
    store: CertAccountRepository,
}

impl CertAccountService {
    pub async fn new(store_provider: LandscapeDBServiceProvider) -> Self {
        let store = store_provider.cert_account_store();
        Self { store }
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
