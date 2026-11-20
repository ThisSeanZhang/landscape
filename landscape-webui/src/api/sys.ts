import type {
  LandscapeStatus,
  LandscapeSystemInfo,
  Capability,
} from "@landscape-router/types/api/schemas";
import { createLandscapeStatus } from "@/lib/sys";

import {
  getBasicSysInfo,
  getIntervalFetchInfo,
  getCpuCount,
  getCapabilities,
} from "@landscape-router/types/api/system-info/system-info";

export async function get_sysinfo(): Promise<LandscapeSystemInfo> {
  return await getBasicSysInfo();
}

export async function get_capabilities(): Promise<Capability[]> {
  return await getCapabilities({ silent: true });
}

export async function interval_fetch_info(): Promise<LandscapeStatus> {
  const data = await getIntervalFetchInfo();
  return createLandscapeStatus(data);
}

export async function get_cpu_count(): Promise<number> {
  return await getCpuCount();
}
