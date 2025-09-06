use std::{collections::HashMap, path::PathBuf};

use config::from_phy_dev;
use dev_wifi::LandscapeWifiInterface;
use futures::stream::TryStreamExt;
use landscape_common::database::repository::Repository;
use landscape_common::database::{LandscapeDBTrait, LandscapeServiceDBTrait};
use landscape_common::{
    config::iface::{IfaceCpuSoftBalance, IfaceZoneType, NetworkIfaceConfig, WifiMode},
    error::LdResult,
    iface::{AddController, BridgeCreate, ChangeZone},
};
use landscape_database::iface::repository::NetIfaceRepository;
use landscape_database::provider::LandscapeDBServiceProvider;
use rtnetlink::new_connection;
use serde::Serialize;
use ts_rs::TS;

use crate::dev::LandscapeInterface;

pub mod config;
pub mod dev_wifi;
pub mod ip;

// 前端渲染拓扑节点
#[derive(Serialize, Debug, Clone)]
pub struct IfaceTopology {
    // 配置
    #[serde(flatten)]
    pub config: NetworkIfaceConfig,
    // 当前的状态: 除了 IP 之类的
    #[serde(flatten)]
    pub status: LandscapeInterface,

    pub wifi_info: Option<LandscapeWifiInterface>,
}

pub async fn get_iface_by_name(name: &str) -> Option<LandscapeInterface> {
    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().match_name(name.to_string()).execute();

    if let Ok(Some(msg)) = links.try_next().await {
        LandscapeInterface::new(msg)
    } else {
        None
    }
}

/// interface manager
#[derive(Clone)]
pub struct IfaceManagerService {
    /// 配置存储
    pub store_service: LandscapeDBServiceProvider,

    pub iface_store: NetIfaceRepository,
}

impl IfaceManagerService {
    pub async fn new(store_service: LandscapeDBServiceProvider) -> Self {
        let store = store_service.iface_store();
        crate::init_devs(store.list_all().await.unwrap()).await;
        drop(store);
        Self {
            iface_store: store_service.iface_store(),
            store_service,
        }
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
        let all_config = self.get_iface_configs().await;

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
        let all_config = self.get_iface_configs().await;
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
            self.del_iface_config(name).await;
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
        let iface_info = crate::change_dev_status(&iface_name, enable_in_boot).await;

        if let Some(iface_info) = iface_info {
            let mut link_config = if let Some(link_config) = self.get_iface_config(iface_name).await
            {
                link_config
            } else {
                from_phy_dev(&iface_info)
            };
            link_config.enable_in_boot = enable_in_boot;

            self.set_iface_config(link_config).await;
        }
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
                    reset_iface_balance(&link_config.name).unwrap();
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
        store.find_by_iface_name(key).await.ok()?
    }

    pub async fn del_iface_config(&self, key: String) -> bool {
        let store = self.store_service.iface_store();
        let res = store.delete(key).await;
        match res {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    async fn get_iface_configs(&self) -> Vec<NetworkIfaceConfig> {
        let store = self.store_service.iface_store();
        store.list().await.unwrap()
    }

    pub async fn get_all_wan_iface_config(&self) -> Vec<NetworkIfaceConfig> {
        self.iface_store.get_all_wan_iface().await.unwrap_or_default()
    }
}

/// 已管理的网卡
#[derive(Serialize, Debug, Clone, TS)]
#[ts(export, export_to = "iface.ts")]
pub struct IfaceInfo {
    /// 持久化的配置
    pub config: NetworkIfaceConfig,
    /// 当前网卡的配置, 可能网卡现在不存在
    pub status: Option<LandscapeInterface>,
    pub wifi_info: Option<LandscapeWifiInterface>,
}

/// 未纳入配置的网卡
#[derive(Serialize, Debug, Clone, TS)]
#[ts(export, export_to = "iface.ts")]
pub struct RawIfaceInfo {
    /// 当前网卡的配置
    pub status: LandscapeInterface,
    pub wifi_info: Option<LandscapeWifiInterface>,
}

#[derive(Clone, Serialize, TS)]
#[ts(export, export_to = "iface.ts")]
pub struct IfacesInfo {
    managed: Vec<IfaceInfo>,
    unmanaged: Vec<RawIfaceInfo>,
}
fn reset_iface_balance(iface_name: &str) -> LdResult<()> {
    setting_iface_balance(iface_name, IfaceCpuSoftBalance { xps: "0".into(), rps: "0".into() })
}

pub(crate) fn setting_iface_balance(
    iface_name: &str,
    balance: IfaceCpuSoftBalance,
) -> LdResult<()> {
    let xps_cpus_path =
        PathBuf::from(format!("/sys/class/net/{}/queues/tx-0/xps_cpus", iface_name));
    let rps_cpus_path =
        PathBuf::from(format!("/sys/class/net/{}/queues/rx-0/rps_cpus", iface_name));

    if xps_cpus_path.exists() {
        if let Err(e) = std::fs::write(xps_cpus_path, balance.xps) {
            // TODO: define error
            tracing::error!("setting xps_cpus error: {:?}", e);
        }
    }

    if rps_cpus_path.exists() {
        if let Err(e) = std::fs::write(rps_cpus_path, balance.rps) {
            // TODO: define error
            tracing::error!("setting rps_cpus error: {:?}", e);
        }
    }
    Ok(())
}

pub fn cpu_nums() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

#[cfg(test)]
mod tests {

    use landscape_common::config::iface::IfaceCpuSoftBalance;

    use super::setting_iface_balance;

    #[test]
    fn test_setting_balance() {
        setting_iface_balance("ens6", IfaceCpuSoftBalance { xps: "6".into(), rps: "6".into() })
            .unwrap();
    }

    #[test]
    fn test_reset_balance() {
        super::reset_iface_balance("ens6").unwrap();
    }
}
