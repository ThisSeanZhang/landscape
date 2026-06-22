use landscape_common::enrolled_device::EnrolledDevice;
use landscape_common::event::hub::{EnrolledDeviceEvent, EnrolledDeviceEventSender};
use landscape_database::enrolled_device::repository::EnrolledDeviceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::repository::Repository;
use uuid::Uuid;

#[derive(Clone)]
pub struct EnrolledDeviceService {
    store: EnrolledDeviceRepository,
    dhcp_repo: landscape_database::dhcp_v4_server::repository::DHCPv4ServerRepository,
    device_sender: EnrolledDeviceEventSender,
}

impl EnrolledDeviceService {
    pub async fn new(
        store_provider: LandscapeDBServiceProvider,
        device_sender: EnrolledDeviceEventSender,
    ) -> Self {
        let store = store_provider.enrolled_device_store();
        let dhcp_repo = store_provider.dhcp_v4_server_store();
        Self { store, dhcp_repo, device_sender }
    }

    pub async fn list(&self) -> Vec<EnrolledDevice> {
        match self.store.list_all().await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to list mac bindings: {:?}", e);
                vec![]
            }
        }
    }

    pub async fn get(&self, id: Uuid) -> Option<EnrolledDevice> {
        self.store.find_by_id(id).await.ok().flatten()
    }

    pub async fn push(&self, data: EnrolledDevice) -> Result<(), String> {
        // Validate custom DHCP options
        landscape_common::dhcp::v4_server::config::validate_custom_options(
            &data.dhcp_custom_options,
        )
        .map_err(|e| e.to_string())?;
        // Validate filter option codes
        landscape_common::dhcp::v4_server::config::validate_filter_options(
            &data.dhcp_filter_options,
        )
        .map_err(|e| e.to_string())?;

        // Validate IPv4 is within the specified interface's DHCP range
        if let (Some(iface), Some(ipv4)) = (&data.iface_name, &data.ipv4) {
            let ip_u32 = u32::from(*ipv4);
            let is_valid = self
                .dhcp_repo
                .is_ip_in_subnet(iface.clone(), ip_u32)
                .await
                .map_err(|e| e.to_string())?;

            if !is_valid {
                return Err(format!(
                    "IPv4 address {} is not within the DHCP range of interface {}",
                    ipv4, iface
                ));
            }
        }

        if let Some(existing) = self.store.find_by_mac(data.mac.to_string()).await? {
            if existing.id != data.id {
                return Err(format!("MAC address {} already has an existing binding", data.mac));
            }
        }

        // Validate IPv4 is not already assigned to another MAC
        if let Some(ipv4) = &data.ipv4 {
            // Check if IPv4 is the reserved unspecified address (0.0.0.0)
            if ipv4.is_unspecified() {
                return Err(
                    "IPv4 address 0.0.0.0 is reserved and cannot be used for static binding"
                        .to_string(),
                );
            }

            if let Some(existing) =
                self.store.find_by_ipv4(*ipv4).await.map_err(|e| e.to_string())?
            {
                if existing.id != data.id {
                    return Err(format!(
                        "IPv4 address {} is already assigned to MAC {}",
                        ipv4, existing.mac
                    ));
                }
            }
        }

        // Validate IPv6 is not already assigned to another MAC
        if let Some(ipv6) = &data.ipv6 {
            // Check if IPv6 is the reserved unspecified address (::)
            if ipv6.is_unspecified() {
                return Err(
                    "IPv6 address :: is reserved and cannot be used for static binding".to_string()
                );
            }

            if let Some(existing) =
                self.store.find_by_ipv6(*ipv6).await.map_err(|e| e.to_string())?
            {
                if existing.id != data.id {
                    return Err(format!(
                        "IPv6 address {} is already assigned to MAC {}",
                        ipv6, existing.mac
                    ));
                }
            }
        }

        let id = data.id;
        let old = self.store.find_by_id(id).await.map_err(|e| e.to_string())?;
        self.store.set_or_update_model(id, data.clone()).await.map_err(|e| e.to_string())?;
        let _ = self.device_sender.send(EnrolledDeviceEvent::Updated { old, new: data }).await;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), String> {
        let old = self.store.find_by_id(id).await.map_err(|e| e.to_string())?;
        self.store.delete_model(id).await.map_err(|e| e.to_string())?;
        if let Some(old) = old {
            let _ = self.device_sender.send(EnrolledDeviceEvent::Deleted { old }).await;
        }
        Ok(())
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
        self.dhcp_repo.is_ip_in_subnet(iface_name, ip_u32).await
    }

    pub async fn find_out_of_range_bindings(
        &self,
        iface_name: String,
        server_ip: std::net::Ipv4Addr,
        mask: u8,
    ) -> Result<Vec<EnrolledDevice>, String> {
        self.store
            .find_out_of_range_bindings(iface_name, server_ip, mask)
            .await
            .map_err(|e| e.to_string())
    }
}
