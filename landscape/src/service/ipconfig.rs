use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use landscape_common::{
    args::LAND_HOSTNAME, store::storev2::LandScapeStore, LANDSCAPE_DEFAULT_LAN_NAME,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use crate::{
    dev::LandScapeInterface,
    dhcp_server::{dhcp_server::init_dhcp_server, DhcpServerIpv4Config},
    iface::{
        config::{IfaceZoneType, NetworkIfaceConfig},
        get_iface_by_name,
    },
    service::ServiceStatus,
};

use super::WatchServiceStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IfaceIpServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub ip_model: IfaceIpModelConfig,
}

impl LandScapeStore for IfaceIpServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

impl IfaceIpServiceConfig {
    pub fn get_default_lan_bridge() -> IfaceIpServiceConfig {
        IfaceIpServiceConfig {
            iface_name: LANDSCAPE_DEFAULT_LAN_NAME.into(),
            enable: true,
            ip_model: IfaceIpModelConfig::DhcpServer(DhcpServerIpv4Config::default()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum IfaceIpModelConfig {
    #[default]
    Nothing,
    Static {
        #[serde(default)]
        default_router_ip: Option<Ipv4Addr>,
        #[serde(default)]
        default_router: bool,
        #[serde(default)]
        ipv4: Option<Ipv4Addr>,
        #[serde(default)]
        ipv4_mask: u8,
        #[serde(default)]
        ipv6: Option<Ipv6Addr>,
    },
    PPPoE {
        #[serde(default)]
        default_router: bool,
        username: String,
        password: String,
        mtu: u32,
    },
    DhcpClient {
        #[serde(default)]
        default_router: bool,
        hostname: Option<String>,
    },
    DhcpServer(DhcpServerIpv4Config),
}

impl IfaceIpModelConfig {
    /// 检查当前的 zone 设置是否满足 IP 配置的要求
    pub fn check_iface_status(&self, iface_config: &NetworkIfaceConfig) -> bool {
        match self {
            IfaceIpModelConfig::PPPoE { .. } => {
                matches!(iface_config.zone_type, IfaceZoneType::Wan)
            }
            IfaceIpModelConfig::DhcpClient { .. } => {
                matches!(iface_config.zone_type, IfaceZoneType::Wan)
            }
            IfaceIpModelConfig::DhcpServer { .. } => {
                matches!(iface_config.zone_type, IfaceZoneType::Lan)
            }
            _ => true,
        }
    }
}

type ServiceStatusAndConfigPair = (WatchServiceStatus, mpsc::Sender<IfaceIpServiceConfig>);

#[derive(Clone)]
pub struct IpConfigManager {
    pub services: Arc<RwLock<HashMap<String, ServiceStatusAndConfigPair>>>,
}

impl IpConfigManager {
    pub async fn init(init_config: Vec<IfaceIpServiceConfig>) -> IpConfigManager {
        //
        let services = HashMap::new();
        let services = Arc::new(RwLock::new(services));

        for config in init_config.into_iter() {
            new_iface_service_thread(config, services.clone()).await;
        }

        IpConfigManager { services }
    }

    pub async fn start_new_service(&self, service_config: IfaceIpServiceConfig) -> Result<(), ()> {
        let read_lock = self.services.read().await;
        if let Some((_, sender)) = read_lock.get(&service_config.iface_name) {
            // TODO: 增加响应, 如果插入不了提示说当前已有配置正在配置中
            let result = if let Err(e) = sender.try_send(service_config) {
                match e {
                    mpsc::error::TrySendError::Full(_) => {
                        tracing::error!("已经有配置在等待了");
                        Err(())
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        tracing::error!("内部错误");
                        Err(())
                    }
                }
            } else {
                Ok(())
            };
            drop(read_lock);
            result
        } else {
            drop(read_lock);
            new_iface_service_thread(service_config, self.services.clone()).await;
            Ok(())
        }
    }
}

async fn new_iface_service_thread(
    service_config: IfaceIpServiceConfig,
    services: Arc<RwLock<HashMap<String, ServiceStatusAndConfigPair>>>,
) {
    let (tx, mut rx) = mpsc::channel::<IfaceIpServiceConfig>(1);
    let iface_name_clone = service_config.iface_name.clone();
    let _ = tx.send(service_config).await;
    let mut write_lock = services.write().await;

    let current_status = WatchServiceStatus::default();
    write_lock.insert(iface_name_clone.clone(), (current_status.clone(), tx));
    drop(write_lock);
    tokio::spawn(async move {
        let mut iface_status: Option<WatchServiceStatus> = Some(current_status);
        while let Some(config) = rx.recv().await {
            if let Some(exist_status) = iface_status.take() {
                exist_status.stop().await;
                drop(exist_status);
            }

            let status = if config.enable {
                if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                    init_service_from_config(iface, config.ip_model).await
                } else {
                    let current_status = WatchServiceStatus::default();
                    current_status.0.send_replace(ServiceStatus::Stop {
                        message: Some("can not find iface by name: ".into()),
                    });
                    current_status
                }
            } else {
                WatchServiceStatus::default()
            };

            iface_status = Some(status.clone());
            let mut write_lock = services.write().await;
            if let Some((target, _)) = write_lock.get_mut(&config.iface_name) {
                *target = status;
            } else {
                break;
            }
            drop(write_lock);
        }

        if let Some(exist_status) = iface_status.take() {
            exist_status.stop().await;
        }
    });
}

async fn init_service_from_config(
    iface: LandScapeInterface,
    service_config: IfaceIpModelConfig,
) -> WatchServiceStatus {
    // let _ = std::process::Command::new("ip").args(&["addr", "flush", "dev", iface_name]).output();
    let iface_status = WatchServiceStatus::default();
    let ip_config = iface_status.0.clone();

    match service_config {
        IfaceIpModelConfig::Nothing => {}
        IfaceIpModelConfig::Static {
            default_router, default_router_ip, ipv4, ipv4_mask, ..
        } => {
            // TODO: IPV6 的设置
            if let Some(ipv4) = ipv4 {
                let ipconfig_clone = ip_config.clone();
                let iface_name_clone = iface.name.clone();
                tokio::spawn(async move {
                    let iface_name = iface_name_clone;
                    let ip_config = ipconfig_clone;
                    ip_config.send_replace(ServiceStatus::Staring);
                    // let ipv4 = Ipv4Addr::new(ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
                    tracing::info!("set ipv4 is: {}", ipv4);
                    let _ = std::process::Command::new("ip")
                        .args(&[
                            "addr",
                            "add",
                            &format!("{}/{}", ipv4, ipv4_mask),
                            "dev",
                            &iface_name,
                        ])
                        .output();
                    tracing::debug!("start setting");
                    landscape_ebpf::map_setting::add_wan_ip(iface.index, ipv4);

                    if default_router {
                        if let Some(default_router_ip) = default_router_ip {
                            if !default_router_ip.is_broadcast()
                                && !default_router_ip.is_unspecified()
                                && !default_router_ip.is_loopback()
                            {
                                tracing::info!("setting default route: {:?}", default_router_ip);
                                let result = std::process::Command::new("ip")
                                    .args(&[
                                        "route",
                                        "replace",
                                        "default",
                                        "via",
                                        &format!("{}", default_router_ip),
                                        "dev",
                                        &iface_name,
                                    ])
                                    .output();
                                if let Err(e) = result {
                                    tracing::error!("replace route error: {e:?}")
                                }
                            }
                        }
                    }

                    ip_config.send_replace(ServiceStatus::Running);

                    let mut config_recv = ip_config.subscribe();
                    let _ = config_recv
                        .wait_for(|s| {
                            matches!(s, ServiceStatus::Stopping)
                                || matches!(s, ServiceStatus::Stop { .. })
                        })
                        .await;
                    let _ = std::process::Command::new("ip")
                        .args(&[
                            "addr",
                            "del",
                            &format!("{}/{}", ipv4, ipv4_mask),
                            "dev",
                            &iface_name,
                        ])
                        .output();

                    landscape_ebpf::map_setting::del_wan_ip(iface.index);
                    ip_config.send_replace(ServiceStatus::Stop { message: None });
                });
            }
        }
        IfaceIpModelConfig::PPPoE { username, password, mtu: _, .. } => {
            if let Some(mac_addr) = iface.mac {
                let iface_name = iface.name.clone();
                let service_status = ip_config.clone();
                tokio::spawn(async move {
                    crate::pppoe_client::pppoe_client_v2::create_pppoe_client(
                        iface.index,
                        iface_name,
                        mac_addr,
                        username,
                        password,
                        service_status,
                    )
                    .await;
                });
            } else {
                ip_config.send_replace(ServiceStatus::Stop {
                    message: Some("mac addr is empty".into()),
                });
            }
        }
        IfaceIpModelConfig::DhcpClient { default_router, hostname } => {
            if let Some(mac_addr) = iface.mac {
                let iface_name = iface.name.clone();
                let service_status = ip_config.clone();

                let hostname =
                    hostname.filter(|h| !h.is_empty()).unwrap_or_else(|| LAND_HOSTNAME.clone());

                tokio::spawn(async move {
                    crate::dhcp_client::dhcp_client(
                        iface.index,
                        iface_name,
                        mac_addr,
                        68,
                        service_status,
                        hostname,
                        default_router,
                    )
                    .await;
                });
            } else {
                ip_config.send_replace(ServiceStatus::Stop {
                    message: Some("mac addr is empty".into()),
                });
            }
        }
        IfaceIpModelConfig::DhcpServer(config) => {
            tracing::info!("使用的  DHCP server 配置是: {config:?}");
            init_dhcp_server(iface.name.clone(), config, ip_config.clone()).await;
        }
    };

    iface_status
}
