import type {
  LandscapeSystemInfo as LandscapeSystemInfoType,
  CpuUsage,
  MemUsage,
  LoadAvg,
  LandscapeStatus as LandscapeStatusType,
} from "@landscape-router/types/api/schemas";

export type LandscapeSystemInfo = LandscapeSystemInfoType;
export type { CpuUsage, MemUsage, LoadAvg };

export class LandscapeStatus implements LandscapeStatusType {
  global_cpu_info: number;
  global_cpu_temp?: number;
  cpus: CpuUsage[];
  mem: MemUsage;
  uptime: number;
  load_avg: LoadAvg;

  constructor(obj?: LandscapeStatusType) {
    this.global_cpu_info = obj?.global_cpu_info ?? 0;
    this.global_cpu_temp = obj?.global_cpu_temp;
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
