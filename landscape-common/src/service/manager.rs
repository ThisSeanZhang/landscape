use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;

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
    /// - 启动中收到停止请求时，管理器会等本方法返回，再停止并等待返回的实例。
    async fn start(&self, config: Self::Config) -> ServiceHandle;
}

// The FIFO and its waiting senders belong to the registration across worker failures.
struct ServiceRegistration<C> {
    runs: Arc<ServiceRuns<C>>,
    config_tx: mpsc::Sender<C>,
    worker: watch::Receiver<Option<AbortHandle>>,
    stopped: CancellationToken,
}

// A supervisor may disappear with its Tokio runtime. Keep the worker joinable
// by its successor, including when the original worker is still running.
struct WorkerTask {
    join: AsyncMutex<Option<JoinHandle<()>>>,
    changed: watch::Sender<Option<AbortHandle>>,
}

struct ServiceRegistryEntry<C> {
    registration: Arc<ServiceRegistration<C>>,
    worker: Arc<WorkerTask>,
    supervisor: Option<JoinHandle<()>>,
    supervisor_done: CancellationToken,
}

// A replacement worker resumes the same receiver and any config dequeued before
// the previous run finished draining. Producers never take this lock.
struct RunQueue<C> {
    configs: mpsc::Receiver<C>,
    pending: Option<C>,
}

struct ServiceRuns<C> {
    queue: AsyncMutex<RunQueue<C>>,
    current: Mutex<ServiceHandle>,
    stop: CancellationToken,
    predecessor: Option<CancellationToken>,
}

impl<C: Send + Sync + 'static> ServiceRuns<C> {
    fn current_run(&self) -> ServiceHandle {
        self.current.lock().unwrap().clone()
    }

    async fn wait_predecessor(&self) {
        if let Some(stopped) = &self.predecessor {
            stopped.cancelled().await;
        }
    }

    async fn drain(&self) {
        self.wait_predecessor().await;
        // If the supervisor itself exited early, a worker can still be returning
        // from start(). Wait for it to publish its handle before reading it.
        let _worker = self.queue.lock().await;
        self.current_run().wait_stop().await;
    }

    fn spawn_worker<H: ServiceStarterTrait<Config = C>>(
        self: &Arc<Self>,
        key: &str,
        starter: Arc<H>,
    ) -> JoinHandle<()> {
        let runs = self.clone();
        spawn_task_with_resource(task_label::task::SERVICE_MANAGER_SPAWN, key, async move {
            runs.wait_predecessor().await;
            let mut queue = runs.queue.lock().await;
            while !runs.stop.is_cancelled() {
                if queue.pending.is_none() {
                    tokio::select! {
                        biased;
                        _ = runs.stop.cancelled() => break,
                        next = queue.configs.recv() => match next {
                            Some(config) => queue.pending = Some(config),
                            None => break,
                        },
                    }
                }
                runs.current_run().wait_stop().await;
                if runs.stop.is_cancelled() {
                    break;
                }
                let config = queue.pending.take().expect("dequeued config");
                // Normal deletion lets start() finish so its returned handle can be drained.
                let run = starter.start(config).await;
                run.supervise_lifecycle();
                *runs.current.lock().unwrap() = run;
            }
        })
    }
}

type ServiceRegistry<C> = Mutex<HashMap<String, ServiceRegistryEntry<C>>>;

enum ConfigDelivery<C> {
    Started,
    Existing(Arc<ServiceRegistration<C>>, CancellationToken, C),
    Closing,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum RestartError {
    #[error("the service registration is closed or missing")]
    Closed,
    #[error("timed out waiting to deliver the restart")]
    TimedOut,
}

#[derive(Clone)]
pub struct ServiceManager<H: ServiceStarterTrait> {
    services: Arc<ServiceRegistry<H::Config>>,
    starter: H,
}

impl<H: ServiceStarterTrait> ServiceManager<H> {
    pub async fn init(init_config: Vec<H::Config>, starter: H) -> Self {
        let manager = Self { services: Arc::default(), starter };
        for config in init_config {
            manager.update_service_wait(config).await;
        }
        manager
    }

    fn spawn_service(
        &self,
        key: &str,
        config: H::Config,
        predecessor: Option<CancellationToken>,
    ) -> ServiceRegistryEntry<H::Config> {
        let (config_tx, configs) = mpsc::channel(1);
        config_tx.try_send(config).expect("a new service queue has room for its first config");
        let runs = Arc::new(ServiceRuns {
            queue: AsyncMutex::new(RunQueue { configs, pending: None }),
            current: Mutex::new(ServiceHandle::new()),
            stop: CancellationToken::new(),
            predecessor,
        });
        let worker = runs.spawn_worker(key, Arc::new(self.starter.clone()));
        let (changed, current_worker) = watch::channel(Some(worker.abort_handle()));
        let mut entry = ServiceRegistryEntry {
            registration: Arc::new(ServiceRegistration {
                config_tx,
                runs,
                worker: current_worker,
                stopped: CancellationToken::new(),
            }),
            worker: Arc::new(WorkerTask { join: AsyncMutex::new(Some(worker)), changed }),
            supervisor: None,
            supervisor_done: CancellationToken::new(),
        };
        self.spawn_supervisor(key, &mut entry);
        entry
    }

    fn spawn_supervisor(&self, key: &str, entry: &mut ServiceRegistryEntry<H::Config>) {
        let runs = entry.registration.runs.clone();
        let worker = entry.worker.clone();
        let starter = Arc::new(self.starter.clone());
        let key = key.to_owned();
        entry.supervisor_done = CancellationToken::new();
        let done = entry.supervisor_done.clone().drop_guard();
        entry.supervisor = Some(spawn_task_with_resource(
            task_label::task::SERVICE_MANAGER_SPAWN,
            key.clone(),
            async move {
                let _done = done;
                let mut join = worker.join.lock().await;
                loop {
                    if let Some(task) = join.as_mut() {
                        // Joining by reference leaves the handle available if this supervisor exits.
                        let result = task.await;
                        *join = None;
                        worker.changed.send_replace(None);
                        match result {
                            Ok(()) => {
                                runs.drain().await;
                                break;
                            }
                            Err(error) => {
                                tracing::error!(key, %error, "service worker exited unexpectedly")
                            }
                        }
                    }
                    if runs.stop.is_cancelled() {
                        runs.drain().await;
                        break;
                    }
                    // Finish interrupted cleanup. An idle worker can be replaced without
                    // stopping a healthy run. The next actual config drives its restart.
                    if runs.current_run().stop_token().is_cancelled() {
                        runs.drain().await;
                    }
                    let task = runs.spawn_worker(&key, starter.clone());
                    worker.changed.send_replace(Some(task.abort_handle()));
                    *join = Some(task);
                }
            },
        ));
    }

    fn ensure_supervisor(&self, key: &str, entry: &mut ServiceRegistryEntry<H::Config>) {
        if entry.supervisor_done.is_cancelled() {
            self.spawn_supervisor(key, entry);
        }
    }

    // Reserve a successor under the same lock as deletion. A later stop targets that
    // successor even while its predecessor is draining. Each has its own FIFO.
    fn register_or_get(
        &self,
        config: H::Config,
        allow_recreation: bool,
    ) -> ConfigDelivery<H::Config> {
        let key = config.service_key();
        let mut services = self.services.lock().unwrap();
        let predecessor = match services.get_mut(&key) {
            None => None,
            Some(entry) if !entry.registration.runs.stop.is_cancelled() => {
                self.ensure_supervisor(&key, entry);
                return ConfigDelivery::Existing(
                    entry.registration.clone(),
                    entry.supervisor_done.clone(),
                    config,
                );
            }
            Some(_) if !allow_recreation => return ConfigDelivery::Closing,
            Some(entry) => Some(entry.registration.stopped.clone()),
        };
        let entry = self.spawn_service(&key, config, predecessor);
        services.insert(key, entry);
        ConfigDelivery::Started
    }

    /// Capture the current registration now, including when the returned future is
    /// polled later. Deletion or worker failure before admission invalidates the request.
    /// Success means it joined this registration's FIFO and survives worker recovery.
    pub fn restart_existing(
        &self,
        config: H::Config,
        timeout: Duration,
    ) -> impl Future<Output = Result<(), RestartError>> + Send + 'static {
        let key = config.service_key();
        let target = self.services.lock().unwrap().get_mut(&key).and_then(|entry| {
            if entry.registration.runs.stop.is_cancelled() {
                return None;
            }
            self.ensure_supervisor(&key, entry);
            let mut changes = entry.registration.worker.clone();
            let worker = changes.borrow_and_update().clone()?;
            Some((entry.registration.clone(), worker, changes))
        });
        async move {
            let (entry, worker, mut changes) = target.ok_or(RestartError::Closed)?;
            let permit = tokio::select! {
                biased;
                _ = entry.runs.stop.cancelled() => return Err(RestartError::Closed),
                _ = changes.changed() => return Err(RestartError::Closed),
                result = tokio::time::timeout(timeout, entry.config_tx.reserve()) =>
                    result.map_err(|_| RestartError::TimedOut)?.map_err(|_| RestartError::Closed)?,
            };
            if worker.is_finished() || entry.runs.stop.is_cancelled() {
                return Err(RestartError::Closed);
            }
            permit.send(config);
            Ok(())
        }
    }

    #[allow(clippy::result_unit_err)] // Internal callers only distinguish success from failure.
    pub async fn update_service(&self, config: H::Config) -> Result<(), ()> {
        match self.register_or_get(config, false) {
            ConfigDelivery::Started => Ok(()),
            ConfigDelivery::Closing => Err(()),
            ConfigDelivery::Existing(entry, _, config) => {
                entry.config_tx.try_send(config).map_err(|err| {
                    tracing::warn!(
                        key = err.into_inner().service_key(),
                        "service queue full or closed"
                    );
                })
            }
        }
    }

    /// Return once the persisted config is enqueued. A new registration can accept its
    /// first config while waiting for the previous registration to finish cleaning up.
    pub async fn update_service_wait(&self, config: H::Config) {
        let key = config.service_key();
        let ConfigDelivery::Existing(registration, mut done, config) =
            self.register_or_get(config, true)
        else {
            return;
        };
        let send = registration.config_tx.send(config);
        tokio::pin!(send);
        loop {
            tokio::select! {
                biased;
                _ = registration.runs.stop.cancelled() => return,
                _ = done.cancelled() => {
                    // Keep the original reservation in the FIFO across supervisor recovery.
                    let mut services = self.services.lock().unwrap();
                    let Some(entry) = services.get_mut(&key) else { return };
                    if !Arc::ptr_eq(&registration, &entry.registration) || registration.runs.stop.is_cancelled() {
                        return;
                    }
                    self.ensure_supervisor(&key, entry);
                    done = entry.supervisor_done.clone();
                }
                _ = &mut send => return,
            }
        }
    }

    /// Deliver a persisted create/update with bounded backpressure. A timeout keeps the
    /// database write intact so the next trigger can converge to the stored config.
    pub async fn deliver_bounded(&self, config: H::Config, timeout: Duration) {
        let key = config.service_key();
        if tokio::time::timeout(timeout, self.update_service_wait(config)).await.is_err() {
            tracing::warn!(
                key,
                "delivery timed out; the stored config will converge on the next trigger"
            );
        }
    }

    pub async fn get_all_status(&self) -> HashMap<String, ServiceStatus> {
        self.services
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, entry)| !entry.registration.runs.stop.is_cancelled())
            .map(|(key, entry)| (key.clone(), entry.registration.runs.current_run().current()))
            .collect()
    }

    // Called with the registry locked. Concurrent stops share one join, and cleanup
    // continues if the request that initiated deletion is dropped.
    fn request_stop(
        &self,
        key: &str,
        entry: &mut ServiceRegistryEntry<H::Config>,
    ) -> Arc<ServiceRegistration<H::Config>> {
        let registration = entry.registration.clone();
        if let Some(supervisor) = entry.supervisor.take() {
            registration.runs.stop.cancel();
            let registry = self.services.clone();
            let closing = registration.clone();
            let key = key.to_owned();
            spawn_task_with_resource(
                task_label::task::SERVICE_MANAGER_STOP,
                key.clone(),
                async move {
                    if let Err(error) = supervisor.await {
                        tracing::error!(key, %error, "service supervisor exited unexpectedly");
                        closing.runs.drain().await;
                    }
                    // A pending recreation may already own this key.
                    let mut services = registry.lock().unwrap();
                    if services
                        .get(&key)
                        .is_some_and(|entry| Arc::ptr_eq(&entry.registration, &closing))
                    {
                        services.remove(&key);
                    }
                    closing.stopped.cancel();
                },
            );
        }
        registration
    }

    /// Withdraw queued restarts and wait through any in-progress start and final cleanup.
    pub async fn stop_service(&self, name: String) -> Option<ServiceStatus> {
        let closing = {
            let mut services = self.services.lock().unwrap();
            self.request_stop(&name, services.get_mut(&name)?)
        };
        closing.stopped.cancelled().await;
        Some(closing.runs.current_run().current())
    }

    pub async fn stop_all(&self) {
        let closing: Vec<_> = {
            let mut services = self.services.lock().unwrap();
            services.iter_mut().map(|(key, entry)| self.request_stop(key, entry)).collect()
        };
        for registration in closing {
            registration.stopped.cancelled().await;
        }
    }
}

#[cfg(test)]
mod tests;
