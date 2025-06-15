import { PPPDServiceConfig } from "@/lib/pppd";
import { ServiceStatus } from "@/lib/services";
import axiosService from ".";

export async function get_all_pppd_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await axiosService.get(`services/pppds/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_all_iface_pppd_config(
  iface_name: string
): Promise<PPPDServiceConfig> {
  let data = await axiosService.get(`services/pppds/${iface_name}`);
  console.log(data.data);
  return data.data;
}

export async function get_iface_pppd_config(
  iface_name: string
): Promise<PPPDServiceConfig> {
  let data = await axiosService.get(`services/pppds/${iface_name}`);
  console.log(data.data);
  return data.data;
}

export async function update_iface_pppd_config(
  pppd_config: PPPDServiceConfig
): Promise<void> {
  let data = await axiosService.post(`services/pppds`, {
    ...pppd_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_pppd(name: string): Promise<void> {
  return axiosService.delete(`services/pppds/${name}`);
}

export async function delete_and_stop_iface_pppd_by_attach_iface_name(
  attach_iface_name: string
): Promise<void> {
  return axiosService.delete(`services/pppds/attach/${attach_iface_name}`);
}

export async function get_attach_iface_pppd_config(
  iface_name: string
): Promise<PPPDServiceConfig[]> {
  let data = await axiosService.get(`services/pppds/attach/${iface_name}`);
  console.log(data.data);
  return data.data;
}
