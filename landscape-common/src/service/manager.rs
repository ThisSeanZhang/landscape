use std::{collections::HashMap, sync::Arc};

use tokio::sync::{mpsc, RwLock};

use crate::concurrency::{spawn_task_with_resource, task_label};
use crate::store::storev2::LandscapeStore;

use super::WatchService;

#[async_trait::async_trait]
pub trait ServiceStarterTrait: Clone + Send + Sync + 'static {
    type Config: LandscapeStore + Send + Sync + 'static;

    /// 核心服务初始化逻辑
    async fn start(&self, config: Self::Config) -> WatchService;
}

// `H::Config` 关联类型要求 bound 才能编译，属于必要约束
#[allow(type_alias_bounds)]
pub type ServiceRegistry<H: ServiceStarterTrait> =
    Arc<RwLock<HashMap<String, (WatchService, mpsc::Sender<H::Config>)>>>;

#[derive(Clone)]
pub struct ServiceManager<H: ServiceStarterTrait> {
    pub services: ServiceRegistry<H>,
    pub starter: H,
}

impl<H: ServiceStarterTrait> ServiceManager<H> {
    pub async fn init(init_config: Vec<H::Config>, starter: H) -> Self {
        let services = HashMap::new();
        let manager = Self { services: Arc::new(RwLock::new(services)), starter };

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
        let starter = self.starter.clone();
        spawn_task_with_resource(
            task_label::task::SERVICE_MANAGER_SPAWN,
            key.clone(),
            async move {
                let mut iface_status: Option<WatchService> = Some(service_status);

                while let Some(config) = rx.recv().await {
                    if let Some(exist_status) = iface_status.take() {
                        exist_status.wait_stop().await;
                    }

                    let key = config.get_store_key();
                    let status = starter.clone().start(config).await;

                    iface_status = Some(status.clone());
                    let mut write_lock = service_map.write().await;
                    if let Some((target, _)) = write_lock.get_mut(&key) {
                        *target = status;
                    } else {
                        tracing::warn!(
                            "service '{key}' removed from map during restart, exiting loop"
                        );
                        break;
                    }
                    drop(write_lock);
                }

                if let Some(exist_status) = iface_status.take() {
                    tracing::debug!("config channel closed, stopping running service");
                    exist_status.wait_stop().await;
                }
            },
        );
    }

    #[allow(clippy::result_unit_err)] // 内部 API：调用方只关心成功与否，无错误详情可传递
    pub async fn update_service(&self, config: H::Config) -> Result<(), ()> {
        let key = config.get_store_key();
        let read_lock = self.services.read().await;
        if let Some((_, sender)) = read_lock.get(&key) {
            let result = if let Err(e) = sender.try_send(config) {
                match e {
                    mpsc::error::TrySendError::Full(_) => {
                        tracing::warn!(key, "config update already pending, dropping new config");
                        Err(())
                    }
                    mpsc::error::TrySendError::Closed(_) => {
                        tracing::error!(key, "service task exited unexpectedly");
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

    pub async fn update_service_wait(&self, config: H::Config) {
        let key = config.get_store_key();
        let sender = {
            let read_lock = self.services.read().await;
            read_lock.get(&key).map(|(_, sender)| sender.clone())
        };

        if let Some(sender) = sender {
            if let Err(error) = sender.send(config).await {
                tracing::warn!(key, "service task exited; recreating it for the saved config");
                self.spawn_service(error.0).await;
            }
        } else {
            self.spawn_service(config).await;
        }
    }

    pub async fn get_all_status(&self) -> HashMap<String, WatchService> {
        let read_lock = self.services.read().await;
        let mut result = HashMap::new();
        for (key, (iface_status, _)) in read_lock.iter() {
            result.insert(key.clone(), iface_status.clone());
        }
        result
    }

    pub async fn stop_service(&self, name: String) -> Option<WatchService> {
        let mut write_lock = self.services.write().await;
        if let Some((iface_status, _)) = write_lock.remove(&name) {
            drop(write_lock);
            iface_status.wait_stop().await;
            Some(iface_status)
        } else {
            None
        }
    }

    pub async fn stop_all(&self) {
        let entries: Vec<(String, WatchService)> = {
            let mut write_lock = self.services.write().await;
            write_lock.drain().map(|(key, (status, _sender))| (key, status)).collect()
        };

        let mut handles = Vec::with_capacity(entries.len());
        for (name, status) in entries {
            handles.push(spawn_task_with_resource(
                task_label::task::SERVICE_MANAGER_STOP,
                name.clone(),
                async move {
                    tracing::info!("Stopping service: {}", name);
                    status.wait_stop().await;
                    tracing::info!("Service stopped: {}", name);
                },
            ));
        }
        for handle in handles {
            let _ = handle.await;
        }
    }
}
