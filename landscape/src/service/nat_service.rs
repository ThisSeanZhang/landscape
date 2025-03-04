use std::{collections::HashMap, sync::Arc};

use landscape_common::store::storev2::LandScapeStore;
use landscape_ebpf::nat::NatConfig;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use crate::{iface::get_iface_by_name, service::ServiceStatus};

use super::WatchServiceStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    #[serde(default)]
    pub nat_config: NatConfig,
}

impl LandScapeStore for NatServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

type ServiceStatusAndConfigPair = (WatchServiceStatus, mpsc::Sender<NatServiceConfig>);

#[derive(Clone)]
pub struct NatServiceManager {
    pub services: Arc<RwLock<HashMap<String, ServiceStatusAndConfigPair>>>,
}

impl NatServiceManager {
    pub async fn init(init_config: Vec<NatServiceConfig>) -> NatServiceManager {
        //
        let services = HashMap::new();
        let services = Arc::new(RwLock::new(services));

        for config in init_config.into_iter() {
            new_iface_service_thread(config, services.clone()).await;
        }

        NatServiceManager { services }
    }

    pub async fn start_new_service(&self, service_config: NatServiceConfig) -> Result<(), ()> {
        let read_lock = self.services.read().await;
        if let Some((_, sender)) = read_lock.get(&service_config.iface_name) {
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
    service_config: NatServiceConfig,
    services: Arc<RwLock<HashMap<String, ServiceStatusAndConfigPair>>>,
) {
    let (tx, mut rx) = mpsc::channel::<NatServiceConfig>(1);
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
                let current_status = WatchServiceStatus::default();
                if let Some(iface) = get_iface_by_name(&config.iface_name).await {
                    let service_status_clone = current_status.0.clone();
                    tokio::spawn(async move {
                        crate::nat::create_nat_service(
                            iface.index as i32,
                            iface.mac.is_some(),
                            config.nat_config,
                            service_status_clone,
                        )
                        .await
                    });
                } else {
                    current_status.0.send_replace(ServiceStatus::Stop {
                        message: Some("can not find iface by name: ".into()),
                    });
                }
                current_status
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
