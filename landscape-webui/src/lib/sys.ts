import type { LandscapeStatus } from "@landscape-router/types/api/schemas";

export function createLandscapeStatus(
  obj: Partial<LandscapeStatus> = {},
): LandscapeStatus {
  return {
    global_cpu_info: obj?.global_cpu_info ?? 0,
    global_cpu_temp: obj?.global_cpu_temp,
    cpus: obj?.cpus ?? [],
    mem: obj?.mem ?? {
      total_mem: 0,
      used_mem: 0,
      total_swap: 0,
      used_swap: 0,
    },
    uptime: obj?.uptime ?? 0,
    load_avg: obj?.load_avg ?? {
      one: 0,
      five: 0,
      fifteen: 0,
    },
  };
}
