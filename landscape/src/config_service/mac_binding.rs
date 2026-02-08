use landscape_common::database::repository::Repository;
use landscape_common::mac_binding::IpMacBinding;
use landscape_database::mac_binding::repository::IpMacBindingRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use uuid::Uuid;

#[derive(Clone)]
pub struct MacBindingService {
    pub(crate) store: IpMacBindingRepository,
}

impl MacBindingService {
    pub async fn new(store_provider: LandscapeDBServiceProvider) -> Self {
        let store = store_provider.ip_mac_binding_store();
        Self { store }
    }

    pub async fn list(&self) -> Vec<IpMacBinding> {
        self.store.list_all().await.unwrap_or_default()
    }

    pub async fn get(&self, id: Uuid) -> Option<IpMacBinding> {
        self.store.find_by_id(id).await.ok().flatten()
    }

    pub async fn push(&self, data: IpMacBinding) -> Result<(), String> {
        let id = data.id;
        self.store.set_or_update_model(id, data).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), String> {
        self.store.delete_model(id).await.map_err(|e| e.to_string())
    }
}
