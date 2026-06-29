use std::collections::HashMap;

pub use landscape_common::iface::{IfaceInfo, IfaceTopology, IfacesInfo, RawIfaceInfo};
use landscape_common::service::controller::ConfigController;
use landscape_common::{
    iface::config::{IfaceCpuSoftBalance, IfaceZoneType, NetworkIfaceConfig, WifiMode},
    iface::{AddController, BridgeCreate, ChangeZone},
};
use landscape_database::iface::repository::NetIfaceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use landscape_database::repository::Repository;

use super::iface_config::from_phy_dev;
use crate::get_iface_by_name;
use crate::wan_service::setting_iface_balance;

/// interface manager
#[derive(Clone)]
pub struct IfaceManagerService {
    /// 配置存储
    pub store_service: LandscapeDBServiceProvider,

    pub store: NetIfaceRepository,
}

impl IfaceManagerService {
    pub async fn new(store_service: LandscapeDBServiceProvider) -> Self {
        let store = store_service.iface_store();
        crate::init_devs(store.list_all().await.unwrap()).await;
        Self { store, store_service }
    }

    pub async fn manage_dev(&self, dev_name: String) {
        if self.get_iface_config(dev_name.clone()).await.is_none() {
            if let Some(iface) = get_iface_by_name(&dev_name).await {
                let config = from_phy_dev(&iface);
                self.set_iface_config(config).await;
            }
        }
    }

    pub async fn old_read_ifaces(&self) -> Vec<IfaceTopology> {
        let all_alive_devs = crate::get_all_devices().await;
        let add_wifi_dev = crate::get_all_wifi_devices().await;
        let all_config = self.list().await;

        let mut comfig_map: HashMap<String, NetworkIfaceConfig> = HashMap::new();
        for config in all_config.into_iter() {
            comfig_map.insert(config.get_iface_name(), config);
        }

        let mut info = vec![];
        for each in all_alive_devs.into_iter() {
            if each.is_lo() {
                continue;
            }
            let config = if let Some(config) = comfig_map.remove(&each.name) {
                config
            } else {
                from_phy_dev(&each)
            };

            let wifi_info = add_wifi_dev.get(&config.name).cloned();
            info.push(IfaceTopology { config, status: each, wifi_info });
        }

        info
    }

    /// 读取所有的配置
    /// 返回已配置的网卡列表和未配置的网卡列表
    pub async fn read_ifaces(&self) -> IfacesInfo {
        let all_config = self.list().await;
        let all_alive_devs = crate::get_all_devices().await;
        let mut all_wifi_dev = crate::get_all_wifi_devices().await;

        // 已有配置的 map
        let mut comfig_map: HashMap<String, NetworkIfaceConfig> = HashMap::new();
        for config in all_config.into_iter() {
            comfig_map.insert(config.get_iface_name(), config);
        }

        let mut managed = vec![];
        let mut unmanaged = vec![];

        for each in all_alive_devs.into_iter() {
            let wifi_info = all_wifi_dev.remove(&each.name);

            if let Some(config) = comfig_map.remove(&each.name) {
                // 如果是已经纳入配置的
                managed.push(IfaceInfo { config, status: Some(each), wifi_info });
            } else {
                unmanaged.push(RawIfaceInfo { status: each, wifi_info });
            };
        }
        IfacesInfo { managed, unmanaged }
    }

    pub async fn create_bridge(&self, bridge_config: BridgeCreate) {
        if crate::create_bridge(bridge_config.name.clone()).await {
            let bridge_info = NetworkIfaceConfig::crate_bridge(bridge_config.name, None);
            self.set_iface_config(bridge_info).await;
        }
    }

    pub async fn delete_bridge(&self, name: String) {
        if crate::delete_bridge(name.clone()).await {
            self.delete(name).await;
        }
    }

    pub async fn set_controller(
        &self,
        AddController {
            link_name,
            link_ifindex: _,
            master_name,
            master_ifindex,
        }: AddController,
    ) {
        let iface_info = crate::set_controller(&link_name, master_ifindex).await;
        if let Some(iface_info) = iface_info {
            let mut link_config = if let Some(link_config) = self.get_iface_config(link_name).await
            {
                link_config
            } else {
                from_phy_dev(&iface_info)
            };
            link_config.controller_name = master_name;
            self.set_iface_config(link_config).await;
        }
    }

    pub async fn change_zone(&self, ChangeZone { iface_name, zone }: ChangeZone) {
        let link_config = if let Some(link_config) = self.get_iface_config(iface_name.clone()).await
        {
            Some(link_config)
        } else {
            if let Some(iface) = get_iface_by_name(&iface_name).await {
                Some(from_phy_dev(&iface))
            } else {
                None
            }
        };

        if let Some(mut link_config) = link_config {
            if matches!(zone, IfaceZoneType::Wan) {
                crate::set_controller(&iface_name, None).await;
                link_config.controller_name = None;
            }
            link_config.zone_type = zone;
            self.set_iface_config(link_config).await;
        }
    }

    pub async fn change_wifi_mode(&self, iface_name: String, mode: WifiMode) {
        let link_config = if let Some(link_config) = self.get_iface_config(iface_name.clone()).await
        {
            Some(link_config)
        } else {
            if let Some(iface) = get_iface_by_name(&iface_name).await {
                Some(from_phy_dev(&iface))
            } else {
                None
            }
        };

        if let Some(mut link_config) = link_config {
            // 如果设置为 client 需要清理 controller 配置
            if matches!(mode, WifiMode::Client) {
                crate::set_controller(&iface_name, None).await;
                link_config.controller_name = None;
            }
            crate::using_iw_change_wifi_mode(&link_config.name, &mode);
            link_config.wifi_mode = mode;
            self.set_iface_config(link_config).await;
        }
    }

    pub async fn change_dev_status(&self, iface_name: String, enable_in_boot: bool) {
        crate::change_dev_status(&iface_name, enable_in_boot).await;
    }

    pub async fn change_dev_boot_status(&self, iface_name: String, enable_in_boot: bool) {
        if enable_in_boot {
            let _ = crate::change_dev_status(&iface_name, true).await;
        }

        let mut link_config =
            if let Some(link_config) = self.get_iface_config(iface_name.clone()).await {
                link_config
            } else if let Some(iface_info) = get_iface_by_name(&iface_name).await {
                from_phy_dev(&iface_info)
            } else {
                return;
            };

        link_config.enable_in_boot = enable_in_boot;
        self.set_iface_config(link_config).await;
    }

    pub async fn change_cpu_balance(
        &self,
        iface_name: String,
        balance: Option<IfaceCpuSoftBalance>,
    ) {
        let link_config = if let Some(link_config) = self.get_iface_config(iface_name.clone()).await
        {
            Some(link_config)
        } else {
            if let Some(iface) = get_iface_by_name(&iface_name).await {
                Some(from_phy_dev(&iface))
            } else {
                None
            }
        };

        if let Some(mut link_config) = link_config {
            match (&link_config.xps_rps, balance) {
                (None, Some(config)) | (Some(_), Some(config)) => {
                    setting_iface_balance(&link_config.name, config.clone()).unwrap();
                    link_config.xps_rps = Some(config);
                }
                (Some(_), None) => {
                    link_config.xps_rps = None;
                    crate::wan_service::setting_iface_balance(
                        &link_config.name,
                        IfaceCpuSoftBalance { xps: "0".into(), rps: "0".into() },
                    )
                    .unwrap();
                }
                (None, None) => {
                    // nothing to do
                }
            }
            self.set_iface_config(link_config).await;
        }
    }

    async fn set_iface_config(&self, config: NetworkIfaceConfig) {
        let store = self.store_service.iface_store();
        store.set_or_update_model(config.name.clone(), config).await.unwrap();
        drop(store);
    }

    pub async fn get_iface_config(&self, key: String) -> Option<NetworkIfaceConfig> {
        let store = self.store_service.iface_store();
        store.find_by_id(key).await.ok()?
    }

    pub async fn get_all_wan_iface_config(&self) -> Vec<NetworkIfaceConfig> {
        self.store.get_all_wan_iface().await.unwrap_or_default()
    }
}

#[async_trait::async_trait]
impl ConfigController for IfaceManagerService {
    type Id = String;

    type Config = NetworkIfaceConfig;

    type DatabseAction = NetIfaceRepository;

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}
