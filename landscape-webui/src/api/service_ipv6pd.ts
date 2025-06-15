import { IPV6PDServiceConfig } from "@/lib/ipv6pd";
import { ServiceStatus } from "@/lib/services";
import axiosService from ".";

export async function get_all_ipv6pd_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await axiosService.get(`services/ipv6pd/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_iface_ipv6pd_config(
  iface_name: string
): Promise<IPV6PDServiceConfig> {
  let data = await axiosService.get(`services/ipv6pd/${iface_name}`);
  console.log(data.data);
  return data.data;
}

// 新建新的 PD Client 配置
export async function update_ipv6pd_config(
  ipv6pd_config: IPV6PDServiceConfig
): Promise<void> {
  let data = await axiosService.post(`services/ipv6pd`, {
    ...ipv6pd_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_ipv6pd(name: string): Promise<void> {
  return axiosService.delete(`services/ipv6pd/${name}`);
}
