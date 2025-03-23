use std::{
    fs::OpenOptions,
    io::Write,
    process::{Command, Stdio},
};

use landscape_common::{
    args::LAND_HOME_PATH,
    service::{
        service_manager::ServiceHandler, DefaultServiceStatus, DefaultWatchServiceStatus,
        ServiceStatus,
    },
    store::storev2::LandScapeStore,
    LANDSCAPE_HOSTAPD_TMP_DIR,
};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

#[derive(Clone)]
pub struct WifiService;

impl ServiceHandler for WifiService {
    type Status = DefaultServiceStatus;

    type Config = WifiServiceConfig;

    async fn initialize(config: WifiServiceConfig) -> DefaultWatchServiceStatus {
        let service_status = DefaultWatchServiceStatus::new();

        if config.enable {
            let status_clone = service_status.clone();
            tokio::spawn(async move {
                create_wifi_service(config.iface_name, config.config, status_clone).await
            });
        }

        service_status
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiServiceConfig {
    pub iface_name: String,
    pub enable: bool,
    pub config: String,
}

impl LandScapeStore for WifiServiceConfig {
    fn get_store_key(&self) -> String {
        self.iface_name.clone()
    }
}

pub async fn create_wifi_service(
    iface_name: String,
    config: String,
    service_status: DefaultWatchServiceStatus,
) {
    service_status.just_change_status(ServiceStatus::Staring);

    let (tx, mut rx) = oneshot::channel::<()>();
    let (other_tx, other_rx) = oneshot::channel::<()>();

    service_status.just_change_status(ServiceStatus::Running);
    let clone_service_status = service_status.clone();
    tokio::spawn(async move {
        let stop_wait = clone_service_status.wait_to_stopping();
        tracing::info!("等待外部停止信号");
        let _ = stop_wait.await;
        tracing::info!("接收外部停止信号");
        let _ = tx.send(());
        tracing::info!("向内部发送停止信号");
    });

    let Ok(config_path) = write_config(&iface_name, &config) else {
        tracing::error!("hostapd 配置写入失败");
        service_status.just_change_status(ServiceStatus::Stop);
        return;
    };

    tracing::info!("hostapd 配置写入成功");
    std::thread::spawn(move || {
        tracing::info!("hostapd 启动中");
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
        tracing::info!("向外部线程发送解除阻塞信号");
        let _ = other_tx.send(());
        delete_config(&iface_name);
    });

    let _ = other_rx.await;
    tracing::info!("结束外部线程阻塞");

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
