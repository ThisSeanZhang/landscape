use std::env;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::sync::watch;

pub static LAND_SYS_BASE_INFO: Lazy<LandScapeSystemInfo> = Lazy::new(LandScapeSystemInfo::new);

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Serialize, Deserialize)]
pub struct LandScapeSystemInfo {
    pub host_name: Option<String>,
    pub system_name: Option<String>,
    pub kernel_version: Option<String>,
    pub os_version: Option<String>,
    pub landscape_version: String,
    pub cpu_arch: Option<String>,
    pub start_at: u64,
}

impl LandScapeSystemInfo {
    pub fn new() -> LandScapeSystemInfo {
        let start_at = System::boot_time();
        let cpu_arch = System::cpu_arch();
        let host_name = System::host_name();
        let system_name = System::name();
        let kernel_version = System::kernel_version();
        let os_version = System::os_version();
        let landscape_version = VERSION.to_string();

        LandScapeSystemInfo {
            start_at,
            host_name,
            system_name,
            kernel_version,
            os_version,
            landscape_version,
            cpu_arch,
        }
    }
}

pub trait WatchResourceTrait: Clone + Serialize + Default {}
impl<T> WatchResourceTrait for T where T: Clone + Serialize + Default {}

#[derive(Clone, Debug)]
pub struct WatchResource<T: WatchResourceTrait>(pub watch::Sender<T>);

impl<T: WatchResourceTrait> WatchResource<T> {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(T::default());
        Self(sender)
    }
}

impl<T: WatchResourceTrait> Serialize for WatchResource<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.borrow().serialize(serializer)
    }
}
