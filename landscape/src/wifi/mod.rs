use landscape_common::database::LandscapeStore;
use landscape_common::database::error::DbError;
use landscape_common::{
    LANDSCAPE_HOSTAPD_TMP_DIR,
    args::LAND_HOME_PATH,
    concurrency::{short_thread_name, spawn_named_thread, task_label, thread_name},
    lan_service::ap::WifiServiceConfig,
    service::{
        ServiceStatus, WatchService,
        controller::{ConfigStoreController, ConfigStoreServiceController},
        manager::{ServiceManager, ServiceStarterTrait},
    },
};
use landscape_database::{
    provider::LandscapeDBServiceProvider, wifi::repository::WifiServiceRepository,
};
use std::{
    fs::OpenOptions,
    io::Write,
    process::{Command, Stdio},
};
use tokio::sync::oneshot;

use crate::get_iface_by_name;

#[derive(Clone, Default)]
pub struct WifiService;

#[async_trait::async_trait]
impl ServiceStarterTrait for WifiService {
    type Config = WifiServiceConfig;

    async fn start(&self, config: WifiServiceConfig) -> WatchService {
        let service_status = WatchService::new();

        if config.enable {
            if get_iface_by_name(&config.iface_name).await.is_some() {
                service_status.just_change_status(ServiceStatus::Staring);
                let iface_name = config.iface_name.clone();
                let spawn_status = service_status.clone();
                let task_status = service_status.clone();
                spawn_status.spawn_task_with_resource(
                    task_label::task::WIFI_RUN,
                    iface_name.clone(),
                    async move {
                        create_wifi_service(config.iface_name, config.config, task_status).await
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
                service_status.just_change_status(ServiceStatus::Staring);
                service_status.just_change_status(ServiceStatus::Failed);
            }
        } else {
            service_status.just_change_status(ServiceStatus::Disabled);
        }

        service_status
    }
}

pub async fn create_wifi_service(iface_name: String, config: String, service_status: WatchService) {
    service_status.just_change_status(ServiceStatus::Staring);

    let (tx, mut rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    service_status.just_change_status(ServiceStatus::Running);
    let stop_token = service_status.stop_token();
    let spawn_status = service_status.clone();
    spawn_status.spawn_task_with_resource(
        task_label::task::WIFI_STOP,
        iface_name.clone(),
        async move {
            tracing::info!("Waiting for external stop signal");
            stop_token.cancelled().await;
            tracing::info!("Received external stop signal");
            let _ = tx.send(());
            tracing::info!("Sent internal stop signal");
        },
    );

    let Ok(config_path) = write_config(&iface_name, &config) else {
        tracing::error!("hostapd 配置写入失败");
        service_status.just_change_status(ServiceStatus::Stop);
        return;
    };

    tracing::info!("hostapd config written successfully");
    spawn_named_thread(short_thread_name(thread_name::prefix::WIFI, &iface_name), move || {
        tracing::info!("Starting hostapd");
        let mut child = match Command::new("hostapd")
            .arg("-i")
            .arg(&iface_name)
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                tracing::error!("启动 hostapd 失败: {}", e);
                return;
            }
        };
        let mut check_error_times = 0;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            match child.try_wait() {
                Ok(Some(status)) => {
                    tracing::warn!("hostapd 退出， 状态码： {:?}", status);
                    break;
                }
                Ok(None) => {
                    check_error_times = 0;
                }
                Err(e) => {
                    tracing::error!("hostapd error: {e:?}");
                    if check_error_times > 3 {
                        break;
                    }
                    check_error_times += 1;
                }
            }

            match rx.try_recv() {
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
                Ok(_) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    tracing::error!("rx, 通知错误");
                    break;
                }
            }
        }
        let _ = child.kill();
        tracing::info!("Sent worker thread exit signal");
        let _ = other_tx.send(());
        delete_config(&iface_name);
    })
    .expect("failed to spawn wifi worker thread");

    let _ = other_rx.await;
    tracing::info!("Worker thread exited");

    service_status.just_change_status(ServiceStatus::Stop);
}

fn write_config(iface_name: &str, config: &str) -> Result<String, ()> {
    let file_dir = LAND_HOME_PATH.join(LANDSCAPE_HOSTAPD_TMP_DIR);
    if !file_dir.exists() {
        std::fs::create_dir_all(&file_dir).unwrap();
    } else {
        if !file_dir.is_dir() {
            tracing::error!("{:?} is not a dir", file_dir);
            return Err(());
        }
    }

    let file_path = file_dir.join(format!("{}.conf", iface_name));
    let path_str = format!("{}", file_path.display());
    tracing::debug!("write config into: {}", path_str);
    let file = OpenOptions::new()
        .write(true) // 打开文件以进行写入
        .truncate(true) // 文件存在时会被截断
        .create(true) // 如果文件不存在，则会创建
        .open(&path_str);

    let mut file = match file {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("打开文件错误: {:?}", e);
            return Err(());
        }
    };

    tracing::debug!("write config: {:?}", config);
    let Ok(_) = file.write_all(config.as_bytes()) else {
        return Err(());
    };

    Ok(path_str)
}
fn delete_config(iface_name: &str) {
    let _ = std::fs::remove_file(
        LAND_HOME_PATH.join(LANDSCAPE_HOSTAPD_TMP_DIR).join(format!("{}.conf", iface_name)),
    );
}

#[derive(Clone)]
pub struct WifiServiceManagerService {
    store: WifiServiceRepository,
    service: ServiceManager<WifiService>,
}

#[async_trait::async_trait]
impl ConfigStoreController for WifiServiceManagerService {
    type Id = String;
    type Config = WifiServiceConfig;
    type Store = WifiServiceRepository;

    fn get_store(&self) -> &Self::Store {
        &self.store
    }
}

impl ConfigStoreServiceController for WifiServiceManagerService {
    type H = WifiService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }
}

impl WifiServiceManagerService {
    pub async fn new(store_service: LandscapeDBServiceProvider) -> Result<Self, DbError> {
        let store = store_service.wifi_service_store();
        let service = ServiceManager::init(store.list().await?, Default::default()).await;

        // let service_clone = service.clone();
        // tokio::spawn(async move {
        //     while let Ok(msg) = dev_observer.recv().await {
        //         match msg {
        //             IfaceObserverAction::Up(iface_name) => {
        //                 tracing::info!("restart {iface_name} Wifi service");
        //                 let service_config = if let Some(service_config) =
        //                     store.find_by_iface_name(iface_name.clone()).await.unwrap()
        //                 {
        //                     service_config
        //                 } else {
        //                     continue;
        //                 };

        //                 let _ = service_clone.update_service(service_config).await;
        //             }
        //             IfaceObserverAction::Down(_) => {}
        //         }
        //     }
        // });

        let store = store_service.wifi_service_store();
        Ok(Self { service, store })
    }
}
