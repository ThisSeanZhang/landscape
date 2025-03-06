use std::{collections::HashMap, fmt::Debug, sync::Arc};

use serde::Serialize;

use service_code::{WatchService, Watchable};
use tokio::sync::{mpsc, watch, RwLock};

use crate::store::storev2::LandScapeStore;

pub mod service_code;
pub mod service_manager;

#[derive(Serialize, Debug, PartialEq, Clone, Default)]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    // 启动中
    Staring,
    // 正在运行
    Running,
    // 正在停止
    Stopping,
    // 停止运行
    #[default]
    Stop,
}

impl ServiceStatus {
    // 检查当前状态是否可以转换到目标状态
    pub fn can_transition_to(&self, target: &ServiceStatus) -> bool {
        matches!(
            (self, target),
            (ServiceStatus::Stop, ServiceStatus::Staring)
                | (ServiceStatus::Staring, ServiceStatus::Running)
                | (ServiceStatus::Staring, ServiceStatus::Stopping)
                | (ServiceStatus::Staring, ServiceStatus::Stop)
                | (ServiceStatus::Running, ServiceStatus::Stopping)
                | (ServiceStatus::Running, ServiceStatus::Stop)
                | (ServiceStatus::Stopping, ServiceStatus::Stop)
        )
    }
}

#[derive(Serialize, Debug, PartialEq, Clone, Default)]
pub struct DefaultServiceStatus(pub ServiceStatus);

impl Watchable for DefaultServiceStatus {
    type HoleData = ();
    fn get_current_status_code(&self) -> ServiceStatus {
        self.0.clone()
    }

    fn modify_curent_status(&mut self, status: ServiceStatus) {
        self.0 = status;
    }

    fn init() -> Self {
        DefaultServiceStatus(ServiceStatus::Staring)
    }

    fn change_status(&mut self, new_status: ServiceStatus, data: Option<()>) -> bool {
        let _ = data;
        if self.0.can_transition_to(&new_status) {
            self.0 = new_status;
        }
        true
    }
}

/// 默认定义的服务监听
pub type DefaultWatchServiceStatus = WatchService<DefaultServiceStatus>;

// pub trait WatchServiceTrait: Clone + Serialize + Default + Debug {
//     fn get_stopping_status(&self) -> Self;

//     // fn get_stopping_status(&self) -> Self;
// }
// // impl<T> WatchServiceTrait for T where T: Clone + Serialize + Default {}

// /// 被观测的服务
// #[derive(Clone, Debug)]
// pub struct WatchService<T: WatchServiceTrait>(pub watch::Sender<T>);

// impl<T: WatchServiceTrait> WatchService<T> {
//     pub fn new() -> Self {
//         let (sender, _) = watch::channel(T::default());
//         Self(sender)
//     }

//     pub fn send_replace(&self, status: T) -> T {
//         self.0.send_replace(status)
//     }

//     pub fn subscribe(&self) -> watch::Receiver<T> {
//         self.0.subscribe()
//     }

//     pub fn send_if_modified<F>(&self, function: F) -> bool
//     where
//         F: FnOnce(&mut T) -> bool,
//     {
//         self.0.send_if_modified(function)
//     }

//     pub async fn changed(&self) -> Result<(), watch::error::RecvError> {
//         self.0.subscribe().changed().await
//     }

//     pub async fn stop(&self) {
//         wait_status_stop(&self.0).await;
//     }

//     pub async fn wait_start(&self) {
//         wait_status_running(&self.0).await;
//     }
// }

// async fn wait_status_stop<T: WatchServiceTrait>(ip_service_status: &watch::Sender<T>) {
//     let mut do_wait = false;
//     ip_service_status.send_if_modified(|status| {
//         tracing::info!("当前服务的状态: {:?}", status);
//         // 修改当前状态, 并决定是否进行等待
//         match status {
//             ServiceStatus::Staring | ServiceStatus::Running => {
//                 *status = ServiceStatus::Stopping;
//                 do_wait = true;
//                 true
//             }
//             ServiceStatus::Stopping => {
//                 do_wait = true;
//                 false
//             }
//             ServiceStatus::Stop { .. } => {
//                 do_wait = false;
//                 false
//             }
//         }
//     });
//     tracing::info!("当前需要等待之前状态结束吗?: {do_wait}");
//     if do_wait {
//         tracing::info!("那么进行等待");
//         // 等待已有 IP 配置服务停止
//         let _ = ip_service_status
//             .subscribe()
//             .wait_for(|status| matches!(status, ServiceStatus::Stop { .. }))
//             .await;
//         tracing::info!("前一个服务等待停止结束");
//     }
//     // let _ = drop(do_wait);
// }

// async fn wait_status_running<T: WatchServiceTrait>(ip_service_status: &watch::Sender<T>) {
//     let mut do_wait = false;

//     if matches!(*ip_service_status.borrow(), ServiceStatus::Staring) {
//         do_wait = true;
//     }
//     if do_wait {
//         let _ = ip_service_status
//             .subscribe()
//             .wait_for(|status| matches!(status, ServiceStatus::Running))
//             .await;
//     }
// }

// impl<T: WatchServiceTrait> Serialize for WatchService<T> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         self.0.borrow().serialize(serializer)
//     }
// }

// #[derive(Serialize, Debug, PartialEq, Clone)]
// #[serde(tag = "t")]
// #[serde(rename_all = "lowercase")]
// pub enum DefaultServiceStatus {
//     // 启动中
//     Staring,
//     // 正在运行
//     Running,
//     // 正在停止
//     Stopping,
//     // 停止运行
//     Stop { message: Option<String> },
// }

// impl Default for DefaultServiceStatus {
//     fn default() -> Self {
//         DefaultServiceStatus::Stop { message: None }
//     }
// }

// type WatchServiceConfigPair<T, S> = (WatchService<T>, mpsc::Sender<S>);

// /// T: 定义被观察的状态
// /// S：存储的配置
// pub struct ServiceManager<T: WatchServiceTrait, S: LandScapeStore> {
//     pub services: Arc<RwLock<HashMap<String, WatchServiceConfigPair<T, S>>>>,
// }

// impl<T: WatchServiceTrait, S: LandScapeStore> ServiceManager<T, S> {
//     pub async fn init(init_config: Vec<S>) -> Self {
//         //
//         let services = HashMap::new();
//         let services = Arc::new(RwLock::new(services));

//         for config in init_config.into_iter() {
//             // new_iface_service_thread(config, services.clone()).await;
//         }

//         Self { services }
//     }
// }
