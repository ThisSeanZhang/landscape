export type SysInfo = {
  host_name: string | undefined;
  system_name: string | undefined;
  kernel_version: string | undefined;
  os_version: string | undefined;
  landscape_version: string | undefined;
  cpu_arch: string | undefined;
  start_at: number; // 启动时间
};

// CPU 使用情况
export type CpuUsage = {
  usage: number; // 使用率
  name: string; // CPU 名称
  vendor_id: string; // 厂商ID
  brand: string; // 品牌
  frequency: number; // 频率
};

// 内存使用情况
export type MemUsage = {
  total_mem: number; // 总内存
  used_mem: number; // 已用内存
  total_swap: number; // 总交换空间
  used_swap: number; // 已用交换空间
};

// 系统负载平均情况
export type LoadAvg = {
  one: number; // 1分钟负载平均
  five: number; // 5分钟负载平均
  fifteen: number; // 15分钟负载平均
};

export class LandscapeStatus {
  global_cpu_info: number; // 全局 CPU 信息
  cpus: CpuUsage[]; // CPU 使用情况数组
  mem: MemUsage; // 内存使用情况
  uptime: number; // 系统运行时间
  load_avg: LoadAvg; // 系统负载平均

  constructor(obj?: {
    global_cpu_info: number;
    cpus: CpuUsage[];
    mem: MemUsage;
    uptime: number;
    load_avg: LoadAvg;
  }) {
    this.global_cpu_info = obj?.global_cpu_info ?? 0;
    this.cpus = obj?.cpus ?? [];
    this.mem = obj?.mem ?? {
      total_mem: 0,
      used_mem: 0,
      total_swap: 0,
      used_swap: 0,
    };
    this.uptime = obj?.uptime ?? 0;
    this.load_avg = obj?.load_avg ?? {
      one: 0,
      five: 0,
      fifteen: 0,
    };
  }
}

export enum ExhibitType {
  Dashboard = "dashboard",
  Line = "line",
}
