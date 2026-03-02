use landscape_common::cert::order::CertOrderConfig;
use landscape_common::service::controller::ConfigController;
use landscape_database::cert_order::repository::CertOrderRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use uuid::Uuid;

#[derive(Clone)]
pub struct CertOrderService {
    store: CertOrderRepository,
}

impl CertOrderService {
    pub async fn new(store_provider: LandscapeDBServiceProvider) -> Self {
        let store = store_provider.cert_order_store();
        Self { store }
    }
}

#[async_trait::async_trait]
impl ConfigController for CertOrderService {
    type Id = Uuid;
    type Config = CertOrderConfig;
    type DatabseAction = CertOrderRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}
