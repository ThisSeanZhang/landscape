use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sysinfo::System;
use tokio::sync::watch;

use crate::VERSION;

pub static LAND_SYS_BASE_INFO: Lazy<LandscapeSystemInfo> = Lazy::new(LandscapeSystemInfo::new);

/// System Basic Information
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeSystemInfo {
    /// Hostname
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub host_name: Option<String>,
    /// System Name (e.g., Linux)
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub system_name: Option<String>,
    /// Kernel Version
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub kernel_version: Option<String>,
    /// OS Version
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub os_version: Option<String>,
    /// Landscape Version
    pub landscape_version: String,
    /// CPU Architecture
    pub cpu_arch: String,
    /// System Start Time (Timestamp)
    pub start_at: u64,
}

impl LandscapeSystemInfo {
    pub fn new() -> LandscapeSystemInfo {
        let start_at = System::boot_time();
        let cpu_arch = System::cpu_arch();
        let host_name = System::host_name();
        let system_name = System::name();
        let kernel_version = System::kernel_version();
        let os_version = System::os_version();
        let landscape_version = VERSION.to_string();

        LandscapeSystemInfo {
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

/// CPU Usage Information
#[derive(Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CpuUsage {
    /// CPU Usage Percentage
    pub usage: f32,
    /// CPU Name
    pub name: String,
    /// Vendor ID
    pub vendor_id: String,
    /// Brand
    pub brand: String,
    /// Frequency in MHz
    pub frequency: u64,
    /// Temperature in Celsius (Optional)
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub temperature: Option<f32>,
}

impl From<&sysinfo::Cpu> for CpuUsage {
    fn from(cpu: &sysinfo::Cpu) -> Self {
        CpuUsage {
            usage: cpu.cpu_usage(),
            name: cpu.name().to_string(),
            vendor_id: cpu.vendor_id().to_string(),
            brand: cpu.brand().to_string(),
            frequency: cpu.frequency(),
            temperature: None, // Populated later via Components
        }
    }
}

/// Memory Usage Information
#[derive(Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MemUsage {
    /// Total Memory in Bytes
    pub total_mem: u64,
    /// Used Memory in Bytes
    pub used_mem: u64,
    /// Total Swap in Bytes
    pub total_swap: u64,
    /// Used Swap in Bytes
    pub used_swap: u64,
}

/// System Load Average
#[derive(Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LoadAvg {
    /// Average load within one minute.
    pub one: f64,
    /// Average load within five minutes.
    pub five: f64,
    /// Average load within fifteen minutes.
    pub fifteen: f64,
}

impl From<sysinfo::LoadAvg> for LoadAvg {
    fn from(sysinfo::LoadAvg { one, five, fifteen }: sysinfo::LoadAvg) -> Self {
        LoadAvg { one, five, fifteen }
    }
}

/// Landscape Runtime Status
#[derive(Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LandscapeStatus {
    /// Global CPU Usage Percentage
    pub global_cpu_info: f32,
    /// Global/Package CPU Temperature in Celsius
    #[cfg_attr(feature = "openapi", schema(nullable = false))]
    pub global_cpu_temp: Option<f32>,
    /// Per-CPU Usage Information
    pub cpus: Vec<CpuUsage>,
    /// Memory Usage Information
    pub mem: MemUsage,
    /// System Uptime in Seconds
    pub uptime: u64,
    /// Load Average Information
    pub load_avg: LoadAvg,
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
