use landscape_common::database::repository::Repository;
use landscape_common::mac_binding::IpMacBinding;
use landscape_database::mac_binding::repository::IpMacBindingRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use uuid::Uuid;

#[derive(Clone)]
pub struct MacBindingService {
    store: IpMacBindingRepository,
    dhcp_repo: landscape_database::dhcp_v4_server::repository::DHCPv4ServerRepository,
}

impl MacBindingService {
    pub async fn new(store_provider: LandscapeDBServiceProvider) -> Self {
        let store = store_provider.ip_mac_binding_store();
        let dhcp_repo = store_provider.dhcp_v4_server_store();
        Self { store, dhcp_repo }
    }

    pub async fn list(&self) -> Vec<IpMacBinding> {
        match self.store.list_all().await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to list mac bindings: {:?}", e);
                vec![]
            }
        }
    }

    pub async fn get(&self, id: Uuid) -> Option<IpMacBinding> {
        self.store.find_by_id(id).await.ok().flatten()
    }

    pub async fn push(&self, data: IpMacBinding) -> Result<(), String> {
        // 校验 IP 是否属于指定网卡的 DHCP 范围内
        if let (Some(iface), Some(ipv4)) = (&data.iface_name, &data.ipv4) {
            let ip_u32 = u32::from(*ipv4);
            let is_valid = self
                .dhcp_repo
                .is_ip_in_range(iface.clone(), ip_u32)
                .await
                .map_err(|e| e.to_string())?;

            if !is_valid {
                return Err(format!("IP 地址 {} 不在网卡 {} 的 DHCP 服务网段范围内", ipv4, iface));
            }
        }

        let id = data.id;
        self.store.set_or_update_model(id, data).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), String> {
        self.store.delete_model(id).await.map_err(|e| e.to_string())
    }

    pub async fn validate_ip_range(
        &self,
        iface_name: String,
        ipv4_str: String,
    ) -> Result<bool, String> {
        let Ok(ipv4) = ipv4_str.parse::<std::net::Ipv4Addr>() else {
            return Err("Invalid IPv4 address".to_string());
        };

        let ip_u32 = u32::from(ipv4);
        self.dhcp_repo.is_ip_in_range(iface_name, ip_u32).await
    }
}
