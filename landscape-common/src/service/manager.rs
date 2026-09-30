use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{RwLock, mpsc};

use crate::concurrency::{spawn_task_with_resource, task_label};

use super::{STATUS_POLL_INTERVAL, ServiceStatus, StartOutcome, WatchService};

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
    ///   汇报 `Disabled`(观测为 [`StartOutcome::CleanStop`]),不得返回
    ///   未写入的初始 `Stop`(否则被误报为 [`StartOutcome::Stopped`]);
    /// - 服务长驻任务必须经 `handle.spawn_task`/`spawn_task_with_resource`
    ///   注册进 tracker,裸 `tokio::spawn` 的任务无法被 `wait_stop` 等待。
    async fn start(&self, config: Self::Config) -> WatchService;
}

/// 服务注册表条目:状态句柄 + 配置管道 + 运行代数。
///
/// `generation` 在 supervisor 每次 `start()` 落表后递增,供
/// [`ServiceManager::update_service_and_wait`] 识别"由本次更新触发的运行"。
pub(crate) struct ServiceRegistryEntry<H: ServiceStarterTrait> {
    pub(crate) status: WatchService,
    pub(crate) config_tx: mpsc::Sender<H::Config>,
    pub(crate) generation: Arc<AtomicU64>,
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
        let service_status = WatchService::new();

        // 插入到服务映射
        {
            self.services.write().await.insert(
                key.clone(),
                ServiceRegistryEntry {
                    status: service_status.clone(),
                    config_tx: tx,
                    generation: Arc::new(AtomicU64::new(0)),
                },
            );
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

                    let key = config.service_key();
                    let status = starter.clone().start(config).await;
                    // OTP monitor:关闭 tracker 入口并挂死亡监视,
                    // 静默死亡(任务全部退出但状态未到终态)收敛到 Failed
                    status.supervise_lifecycle();

                    iface_status = Some(status.clone());
                    let mut write_lock = service_map.write().await;
                    if let Some(entry) = write_lock.get_mut(&key) {
                        entry.status = status;
                        entry.generation.fetch_add(1, Ordering::SeqCst);
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

    /// 发送配置并观测"由本次更新触发的运行"的启动结果。
    ///
    /// 供 controller 层实现"验证后落库"(Running 才持久化)或"落库后验证"
    /// (非 Running 双回滚)。
    ///
    /// 通过注册表 `generation` 识别新运行:记录发送前的代数,等待代数前进后
    /// 取新句柄观测启动结果。注意:同一 key 存在并发更新时,观测到的运行
    /// 可能属于先于本配置入队的另一更新(队列容量 1,最终状态仍收敛到最后
    /// 一份配置);单写者场景下语义精确。配置投递失败(通道满被去重或服务
    /// 任务退出)不会产生新运行,映射为 [`StartOutcome::NotDelivered`],
    /// 与 [`StartOutcome::Stopped`](真实经历过一次运行后停止)区分。
    pub async fn update_service_and_wait(
        &self,
        config: H::Config,
        timeout: Duration,
    ) -> StartOutcome {
        let key = config.service_key();
        let captured_generation = {
            let read_lock = self.services.read().await;
            read_lock.get(&key).map(|entry| entry.generation.load(Ordering::SeqCst))
        };
        // None: 新键,等待首次真实启动(placeholder 的 generation 0 → 1)
        // Some(n): 既有键,等待代数前进到 n+1
        let target_generation = captured_generation.map_or(1, |current| current + 1);

        if self.update_service(config).await.is_err() {
            return StartOutcome::NotDelivered;
        }

        self.observe_start_outcome(&key, target_generation, tokio::time::Instant::now() + timeout)
            .await
    }

    /// 等待容量地发送配置并观测启动结果(有界 best-effort 投递)。
    ///
    /// 与 [`ServiceManager::update_service`] 的 try_send(通道满即弃)不同,
    /// 本方法等待通道容量;与 [`ServiceManager::update_service_wait`] 的无界
    /// 等待不同,投递与观测共享同一个 deadline,超时即放弃并返回
    /// [`StartOutcome::Timeout`] —— **不保证收敛,仅由调用方告警**。服务任务
    /// 退出(通道关闭)时重建服务后继续观测。
    ///
    /// generation 语义与 [`ServiceManager::update_service_and_wait`] 相同:
    /// 并发更新下先前进的代数可能属于队列中 pending 的前一更新,单写者
    /// 场景下语义精确。
    pub(crate) async fn update_service_wait_and_observe(
        &self,
        config: H::Config,
        timeout: Duration,
    ) -> StartOutcome {
        let key = config.service_key();
        let deadline = tokio::time::Instant::now() + timeout;

        // 先取发送端与代数再放锁:send 背压等待期间持读锁,
        // 会与 spawn_service/观测循环的写锁互等
        let existing = {
            let read_lock = self.services.read().await;
            read_lock
                .get(&key)
                .map(|entry| (entry.config_tx.clone(), entry.generation.load(Ordering::SeqCst)))
        };

        let target_generation = match existing {
            Some((sender, captured)) => {
                match tokio::time::timeout_at(deadline, sender.send(config)).await {
                    Ok(Ok(())) => captured + 1,
                    Ok(Err(error)) => {
                        tracing::warn!(key, "service task exited; recreating it for convergence");
                        self.spawn_service(error.0).await;
                        // 重建条目从 generation 0 重新计数
                        1
                    }
                    Err(_) => {
                        tracing::warn!(key, "delivery timed out; giving up (bounded best-effort)");
                        return StartOutcome::Timeout;
                    }
                }
            }
            None => {
                self.spawn_service(config).await;
                1
            }
        };

        self.observe_start_outcome(&key, target_generation, deadline).await
    }

    /// 观测由一次已投递更新触发的运行:等待代数前进后取新句柄看启动结果。
    async fn observe_start_outcome(
        &self,
        key: &str,
        target_generation: u64,
        deadline: tokio::time::Instant,
    ) -> StartOutcome {
        loop {
            let (status, generation) = {
                let read_lock = self.services.read().await;
                match read_lock.get(key) {
                    Some(entry) => (entry.status.clone(), entry.generation.load(Ordering::SeqCst)),
                    // 服务被并发删除:本次更新不会再产生运行
                    None => return StartOutcome::Stopped,
                }
            };
            if generation >= target_generation {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return StartOutcome::Timeout;
                }
                return status.wait_start_outcome(remaining).await;
            }
            if tokio::time::Instant::now() >= deadline {
                return StartOutcome::Timeout;
            }
            tokio::time::sleep(STATUS_POLL_INTERVAL).await;
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
        let entries: Vec<(String, WatchService)> = {
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
