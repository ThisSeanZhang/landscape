use std::{collections::HashMap, sync::Arc};

use landscape_common::store::storev2::LandScapeStore;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, RwLock};

use crate::pppd_client::PPPDConfig;

use super::WatchServiceStatus;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PPPDServiceConfig {
    pub attach_iface_name: String,
    pub iface_name: String,
    pub enable: bool,
    pub pppd_config: PPPDConfig,
}

impl LandScapeStore for PPPDServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

type ServiceStatusAndConfigPair = (WatchServiceStatus, mpsc::Sender<PPPDServiceConfig>);

#[derive(Clone)]
pub struct PPPDServiceManager {
    pub services: Arc<RwLock<HashMap<String, ServiceStatusAndConfigPair>>>,
}

impl PPPDServiceManager {
    pub async fn init(init_config: Vec<PPPDServiceConfig>) -> PPPDServiceManager {
        //
        let services = HashMap::new();
        let services = Arc::new(RwLock::new(services));

        for config in init_config.into_iter() {
            new_iface_service_thread(config, services.clone()).await;
        }

        PPPDServiceManager { services }
    }

    pub async fn start_new_service(&self, service_config: PPPDServiceConfig) -> Result<(), ()> {
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
    service_config: PPPDServiceConfig,
    services: Arc<RwLock<HashMap<String, ServiceStatusAndConfigPair>>>,
) {
    let (tx, mut rx) = mpsc::channel::<PPPDServiceConfig>(1);
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

            let ppp_iface_name = config.iface_name.clone();
            let status = if config.enable {
                let current_status = WatchServiceStatus::default();
                let service_status_clone = current_status.0.clone();
                tokio::spawn(async move {
                    crate::pppd_client::pppd::create_pppd_thread(
                        config.attach_iface_name,
                        config.iface_name,
                        config.pppd_config,
                        service_status_clone,
                    )
                    .await
                });
                current_status
            } else {
                WatchServiceStatus::default()
            };

            iface_status = Some(status.clone());
            let mut write_lock = services.write().await;
            if let Some((target, _)) = write_lock.get_mut(&ppp_iface_name) {
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
