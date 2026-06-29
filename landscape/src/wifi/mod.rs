use landscape_common::database::LandscapeStore;
use landscape_common::{
    args::LAND_HOME_PATH,
    concurrency::{
        short_thread_name, spawn_named_thread, spawn_task_with_resource, task_label, thread_name,
    },
    iface::wifi::WifiServiceConfig,
    service::{
        controller::ControllerService,
        manager::{ServiceManager, ServiceStarterTrait},
        ServiceStatus, WatchService,
    },
    LANDSCAPE_HOSTAPD_TMP_DIR,
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
            if let Some(_) = get_iface_by_name(&config.iface_name).await {
                let status_clone = service_status.clone();
                let iface_name = config.iface_name.clone();
                spawn_task_with_resource(
                    task_label::task::WIFI_RUN,
                    iface_name.clone(),
                    async move {
                        create_wifi_service(config.iface_name, config.config, status_clone).await
                    },
                );
            } else {
                tracing::error!("Interface {} not found", config.iface_name);
            }
        }

        service_status
    }
}

pub async fn create_wifi_service(iface_name: String, config: String, service_status: WatchService) {
    service_status.just_change_status(ServiceStatus::Staring);

    let (tx, mut rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    service_status.just_change_status(ServiceStatus::Running);
    let clone_service_status = service_status.clone();
    spawn_task_with_resource(task_label::task::WIFI_STOP, iface_name.clone(), async move {
        let stop_wait = clone_service_status.wait_to_stopping();
        tracing::info!("Waiting for external stop signal");
        let _ = stop_wait.await;
        tracing::info!("Received external stop signal");
        let _ = tx.send(());
        tracing::info!("Sent internal stop signal");
    });

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
            .arg(&format!("{}", config_path))
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

    let file_path = file_dir.join(format!("{}.conf", &iface_name));
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
        LAND_HOME_PATH.join(LANDSCAPE_HOSTAPD_TMP_DIR).join(format!("{}.conf", &iface_name)),
    );
}

#[derive(Clone)]
pub struct WifiServiceManagerService {
    store: WifiServiceRepository,
    service: ServiceManager<WifiService>,
}

impl ControllerService for WifiServiceManagerService {
    type Id = String;
    type Config = WifiServiceConfig;
    type DatabseAction = WifiServiceRepository;
    type H = WifiService;

    fn get_service(&self) -> &ServiceManager<Self::H> {
        &self.service
    }

    fn get_repository(&self) -> &Self::DatabseAction {
        &self.store
    }
}

impl WifiServiceManagerService {
    pub async fn new(store_service: LandscapeDBServiceProvider) -> Self {
        let store = store_service.wifi_service_store();
        let service = ServiceManager::init(store.list().await.unwrap(), Default::default()).await;

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
        Self { service, store }
    }
}
