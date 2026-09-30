use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};

use crate::concurrency::{spawn_task_with_resource, task_label};

use super::{ServiceHandle, ServiceStatus};

pub trait ServiceKeyProvider {
    fn service_key(&self) -> String;
}

#[async_trait::async_trait]
pub trait ServiceStarterTrait: Clone + Send + Sync + 'static {
    type Config: ServiceKeyProvider + Send + Sync + 'static;

    /// 核心服务初始化逻辑。
    ///
    /// 契约(由 ServiceHandle 的确定性等待与死亡监视依赖):
    /// - 返回前句柄状态须已进入 `Staring` 或汇报过的终态:禁用配置显式
    ///   汇报 `Disabled`,不得返回未写入的初始 `Stop`;
    /// - 服务长驻任务必须经 `handle.spawn_task`/`spawn_task_with_resource`
    ///   注册进 tracker,裸 `tokio::spawn` 的任务无法被 `wait_stop` 等待。
    async fn start(&self, config: Self::Config) -> ServiceHandle;
}

pub(crate) struct ServiceRegistryEntry<H: ServiceStarterTrait> {
    pub(crate) status: ServiceHandle,
    pub(crate) config_tx: mpsc::Sender<H::Config>,
}

// `H::Config` 关联类型要求 bound 才能编译,属于必要约束
#[allow(type_alias_bounds)]
pub(crate) type ServiceRegistry<H: ServiceStarterTrait> =
    Arc<RwLock<HashMap<String, ServiceRegistryEntry<H>>>>;

#[derive(Clone)]
pub struct ServiceManager<H: ServiceStarterTrait> {
    pub(crate) services: ServiceRegistry<H>,
    pub(crate) starter: H,
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
        let key = service_config.service_key();
        let (tx, mut rx) = mpsc::channel(1);
        let _ = tx.send(service_config).await;
        let service_status = ServiceHandle::new();

        {
            self.services.write().await.insert(
                key.clone(),
                ServiceRegistryEntry { status: service_status.clone(), config_tx: tx },
            );
        }

        let service_map = self.services.clone();
        let starter = self.starter.clone();
        spawn_task_with_resource(
            task_label::task::SERVICE_MANAGER_SPAWN,
            key.clone(),
            async move {
                let mut iface_status: Option<ServiceHandle> = Some(service_status);

                while let Some(config) = rx.recv().await {
                    if let Some(exist_status) = iface_status.take() {
                        exist_status.wait_stop().await;
                    }

                    let key = config.service_key();
                    let status = starter.clone().start(config).await;
                    // OTP monitor:关闭 tracker 入口并挂死亡监视,
                    // 静默死亡(任务全部退出但状态未到终态)收敛到 Failed
                    status.supervise_lifecycle();

                    iface_status = Some(status.clone());
                    let mut write_lock = service_map.write().await;
                    if let Some(entry) = write_lock.get_mut(&key) {
                        entry.status = status;
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

    #[allow(clippy::result_unit_err)] // 内部 API:调用方只关心成功与否,无错误详情可传递
    pub async fn update_service(&self, config: H::Config) -> Result<(), ()> {
        let key = config.service_key();
        let read_lock = self.services.read().await;
        if let Some(entry) = read_lock.get(&key) {
            let result = if let Err(e) = entry.config_tx.try_send(config) {
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
        let key = config.service_key();
        let sender = {
            let read_lock = self.services.read().await;
            read_lock.get(&key).map(|entry| entry.config_tx.clone())
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

    /// 有界背压投递:等待通道容量发送最新已入库配置,超时仅告警不回滚 ——
    /// 库中配置由下一次触发(重启重放、netlink 观察器)收敛。
    /// 服务任务退出(通道关闭)时重建服务。
    pub async fn deliver_bounded(&self, config: H::Config, timeout: Duration) {
        let key = config.service_key();
        let deadline = tokio::time::Instant::now() + timeout;

        // 先取发送端再放锁:send 背压等待期间持读锁,会与写锁互等
        let sender = {
            let read_lock = self.services.read().await;
            read_lock.get(&key).map(|entry| entry.config_tx.clone())
        };

        match sender {
            Some(sender) => match tokio::time::timeout_at(deadline, sender.send(config)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(key, "service task exited; recreating it for the saved config");
                    self.spawn_service(error.0).await;
                }
                Err(_) => {
                    tracing::warn!(
                        key,
                        "delivery timed out; the stored config will converge on the next trigger"
                    );
                }
            },
            None => {
                self.spawn_service(config).await;
            }
        }
    }

    /// 全部服务状态快照(REST 轮询语义:status 是数据,不是信号)
    pub async fn get_all_status(&self) -> HashMap<String, ServiceStatus> {
        let read_lock = self.services.read().await;
        read_lock.iter().map(|(key, entry)| (key.clone(), entry.status.current())).collect()
    }

    pub async fn stop_service(&self, name: String) -> Option<ServiceStatus> {
        let mut write_lock = self.services.write().await;
        if let Some(entry) = write_lock.remove(&name) {
            drop(write_lock);
            entry.status.wait_stop().await;
            Some(entry.status.current())
        } else {
            None
        }
    }

    pub async fn stop_all(&self) {
        let entries: Vec<(String, ServiceHandle)> = {
            let mut write_lock = self.services.write().await;
            write_lock.drain().map(|(key, entry)| (key, entry.status)).collect()
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
