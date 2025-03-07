use std::{collections::HashMap, sync::Arc};

use tokio::sync::{mpsc, RwLock};

use crate::store::storev2::LandScapeStore;

use super::service_code::{WatchService, WatchServiceTrait};

pub trait ServiceHandler {
    type Status: WatchServiceTrait + Send + Sync + 'static;
    type Config: LandScapeStore + Send + Sync + 'static;

    /// 核心服务初始化逻辑
    fn initialize(
        config: Self::Config,
    ) -> impl std::future::Future<Output = WatchService<Self::Status>> + Send;
}
/// T: 定义被观察的状态
/// S：存储的配置
#[derive(Clone)]
pub struct ServiceManager<H: ServiceHandler> {
    pub services: Arc<RwLock<HashMap<String, (WatchService<H::Status>, mpsc::Sender<H::Config>)>>>,
}

impl<H: ServiceHandler> ServiceManager<H> {
    pub async fn init(init_config: Vec<H::Config>) -> Self {
        let services = HashMap::new();
        let manager = Self { services: Arc::new(RwLock::new(services)) };

        for config in init_config {
            manager.spawn_service(config).await;
        }
        manager
    }

    async fn spawn_service(&self, service_config: H::Config) {
        let key = service_config.get_store_key();
        let (tx, mut rx) = mpsc::channel(1);
        let _ = tx.send(service_config).await;
        let service_status = WatchService::new();

        // 插入到服务映射
        {
            self.services.write().await.insert(key.clone(), (service_status.clone(), tx));
        }

        let service_map = self.services.clone();

        tokio::spawn(async move {
            let mut iface_status: Option<WatchService<H::Status>> = Some(service_status);

            while let Some(config) = rx.recv().await {
                if let Some(exist_status) = iface_status.take() {
                    exist_status.wait_stop().await;
                    drop(exist_status);
                }

                let key = config.get_store_key();
                let status = H::initialize(config).await;

                iface_status = Some(status.clone());
                let mut write_lock = service_map.write().await;
                if let Some((target, _)) = write_lock.get_mut(&key) {
                    *target = status;
                } else {
                    break;
                }
                drop(write_lock);
            }

            if let Some(exist_status) = iface_status.take() {
                exist_status.wait_stop().await;
            }
        });
    }

    pub async fn update_service(&self, config: H::Config) -> Result<(), ()> {
        let key = config.get_store_key();
        let read_lock = self.services.read().await;
        if let Some((_, sender)) = read_lock.get(&key) {
            let result = if let Err(e) = sender.try_send(config) {
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
            self.spawn_service(config).await;
            Ok(())
        }
    }
}
