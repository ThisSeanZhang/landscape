import { LandscapeStatus, SysInfo } from "@/lib/sys";
import api from "../api";

export async function get_sysinfo(): Promise<SysInfo> {
  let data = await api.api.get("sysinfo/sys");
  return data.data;
}

export async function interval_fetch_info(): Promise<LandscapeStatus> {
  let data = await api.api.get("sysinfo/interval_fetch_info");
  return data.data;
}
