use landscape_common::info::WatchResource;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

/// CPU Usage
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CpuUsage {
    usage: f32,
    name: String,
    vendor_id: String,
    brand: String,
    frequency: u64,
}

impl From<&sysinfo::Cpu> for CpuUsage {
    fn from(cpu: &sysinfo::Cpu) -> Self {
        CpuUsage {
            usage: cpu.cpu_usage(),
            name: cpu.name().to_string(),
            vendor_id: cpu.vendor_id().to_string(),
            brand: cpu.brand().to_string(),
            frequency: cpu.frequency(),
        }
    }
}

/// 内存使用
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct MemUsage {
    total_mem: u64,
    used_mem: u64,
    total_swap: u64,
    used_swap: u64,
}

#[derive(Clone, Serialize, Deserialize, Default)]
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

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct LandscapeStatus {
    pub global_cpu_info: f32,
    pub cpus: Vec<CpuUsage>,
    pub mem: MemUsage,
    pub uptime: u64,
    pub load_avg: LoadAvg,
}

pub fn get_sys_running_status() -> WatchResource<LandscapeStatus> {
    let status = WatchResource::new();

    let clone_status = status.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut sys = System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );
        loop {
            let mut ld_status = LandscapeStatus::default();
            ld_status.uptime = System::uptime();
            ld_status.load_avg = LoadAvg::from(System::load_average());

            sys.refresh_cpu();

            let cpu = sys.global_cpu_info();
            ld_status.global_cpu_info = cpu.cpu_usage();

            for cpu in sys.cpus() {
                ld_status.cpus.push(CpuUsage::from(cpu));
            }

            sys.refresh_memory();
            ld_status.mem = MemUsage {
                total_mem: sys.total_memory(),
                used_mem: sys.used_memory(),
                total_swap: sys.total_swap(),
                used_swap: sys.used_swap(),
            };

            status.0.send_replace(ld_status);
            interval.tick().await;
        }
    });
    clone_status
}
