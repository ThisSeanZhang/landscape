use serde::Serialize;

use tokio::sync::watch;

pub trait WatchServiceTrait: Clone + Serialize + Default {}
impl<T> WatchServiceTrait for T where T: Clone + Serialize + Default {}

/// 被观测的服务
#[derive(Clone, Debug)]
pub struct WatchService<T: WatchServiceTrait>(pub watch::Sender<T>);

impl<T: WatchServiceTrait> WatchService<T> {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(T::default());
        Self(sender)
    }

    pub fn send_replace(&self, status: T) -> T {
        self.0.send_replace(status)
    }

    pub fn subscribe(&self) -> watch::Receiver<T> {
        self.0.subscribe()
    }

    pub fn send_if_modified<F>(&self, function: F) -> bool
    where
        F: FnOnce(&mut T) -> bool,
    {
        self.0.send_if_modified(function)
    }
}

impl<T: WatchServiceTrait> Serialize for WatchService<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.borrow().serialize(serializer)
    }
}

#[derive(Serialize, Debug, PartialEq, Clone)]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum DefaultServiceStatus {
    // 启动中
    Staring,
    // 正在运行
    Running,
    // 正在停止
    Stopping,
    // 停止运行
    Stop { message: Option<String> },
}

impl Default for DefaultServiceStatus {
    fn default() -> Self {
        DefaultServiceStatus::Stop { message: None }
    }
}

/// 默认定义的服务监听
pub type DefaultWatchServiceStatus = WatchService<DefaultServiceStatus>;
