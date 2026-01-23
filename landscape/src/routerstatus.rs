use landscape_common::info::WatchResource;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use sysinfo::{Components, CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

/// CPU Usage
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CpuUsage {
    usage: f32,
    name: String,
    vendor_id: String,
    brand: String,
    frequency: u64,
    /// Temperature in Celsius (Optional)
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
    /// Global/Package CPU Temperature in Celsius
    pub global_cpu_temp: Option<f32>,
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
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        );
        let mut components = Components::new_with_refreshed_list();

        loop {
            let mut ld_status = LandscapeStatus::default();
            ld_status.uptime = System::uptime();
            ld_status.load_avg = LoadAvg::from(System::load_average());

            sys.refresh_cpu_all();

            // Refresh temperature sensors
            // Pass `false` to only update values of existing components, avoiding expensive re-scanning of /sys/class/hwmon.
            // This ensures negligible performance impact even if called frequently (e.g. 1s).
            components.refresh(false);

            ld_status.global_cpu_info = sys.global_cpu_usage();

            // Logic to map temperatures
            // 1. Find global temperature (Package/Tdie/Tctl)
            // 2. Map per-core temperatures if possible
            let mut global_temp = None;
            let mut core_temps: Vec<(usize, f32)> = Vec::new();
            let mut temp_sum = 0.0;
            let mut temp_count = 0;

            // Prioritize specific labels for global temp
            let mut found_priority = 100;

            for component in &components {
                let label = component.label();
                if let Some(temp) = component.temperature() {
                    // Heuristic for global temp
                    let priority = if label.contains("Package id 0") {
                        1 // Intel Package
                    } else if label.contains("Tdie") {
                        2 // AMD Die
                    } else if label.contains("cpu_thermal") || label.contains("soc_thermal") {
                        3 // Generic / ARM
                    } else if label.contains("Tctl") {
                        4 // AMD Control (often offset, less preferred than Die)
                    } else {
                        100
                    };

                    if priority < found_priority {
                        global_temp = Some(temp);
                        found_priority = priority;
                    }

                    // Heuristic for core temp: "Core 0", "Core 1", etc.
                    // Note: This relies on "Core X" naming convention.
                    if label.starts_with("Core") {
                        if let Some(num_str) = label.split_whitespace().last() {
                            if let Ok(core_idx) = num_str.parse::<usize>() {
                                core_temps.push((core_idx, temp));
                            }
                        }
                        // Also track for average fallback
                        temp_sum += temp;
                        temp_count += 1;
                    }
                }
            }

            // Fallback: if no global package temp found, use average of cores
            if global_temp.is_none() && temp_count > 0 {
                global_temp = Some(temp_sum / temp_count as f32);
            }

            ld_status.global_cpu_temp = global_temp;

            for (i, cpu) in sys.cpus().iter().enumerate() {
                let mut cpu_usage = CpuUsage::from(cpu);

                // Try to find matching core temp
                // Note: sysinfo cpus are usually ordered.
                // Core X sensor usually maps to Physical Core X.
                // For Hyper-Threading (HT), logical CPUs often exceed the number of physical core sensors.
                // Strict mapping (Index i == Core i) is used here to ensure correctness for the first N cores.
                // Logical threads sharing a core (e.g., CPU 4 on Core 0) will NOT inherit the temperature
                // to avoid misleading data if the topology is unknown.
                if let Some((_, temp)) = core_temps.iter().find(|(idx, _)| *idx == i) {
                    cpu_usage.temperature = Some(*temp);
                }

                ld_status.cpus.push(cpu_usage);
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
