import { IfaceIpServiceConfig } from "@/lib/service_ipconfig";
import { ServiceStatus } from "@/lib/services";
import axiosService from ".";

export async function get_all_ipconfig_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await axiosService.get(`services/ipconfigs/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_iface_server_config(
  iface_name: string
): Promise<IfaceIpServiceConfig> {
  let data = await axiosService.get(`services/ipconfigs/${iface_name}`);
  // console.log(data.data);
  return data.data;
}

export async function get_iface_server_status(
  iface_name: string
): Promise<IfaceIpServiceConfig> {
  let data = await axiosService.get(`services/ipconfigs/${iface_name}/status`);
  // console.log(data.data);
  return data.data;
}

export async function update_iface_server_config(
  iface_config: IfaceIpServiceConfig
): Promise<void> {
  let data = await axiosService.post(`services/ipconfigs`, {
    ...iface_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_config(name: string): Promise<void> {
  return axiosService.delete(`services/ipconfigs/${name}`);
}
