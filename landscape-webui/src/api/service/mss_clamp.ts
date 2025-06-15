import axiosService from "@/api";
import { ServiceStatus } from "@/lib/services";
import { MSSClampServiceConfig } from "@/rust_bindings/common/mss_clamp";

export async function get_all_mss_clamp_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await axiosService.get(`services/mss_clamp/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_iface_mss_clamp_config(
  iface_name: string
): Promise<MSSClampServiceConfig> {
  let data = await axiosService.get(`services/mss_clamp/${iface_name}`);
  console.log(data.data);
  return data.data;
}

export async function update_mss_clamp_config(
  mss_clamp_config: MSSClampServiceConfig
): Promise<void> {
  let data = await axiosService.post(`services/mss_clamp`, {
    ...mss_clamp_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_mss_clamp(
  name: string
): Promise<void> {
  return axiosService.delete(`services/mss_clamp/${name}`);
}
