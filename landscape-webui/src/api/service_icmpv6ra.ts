import api from ".";
import { IPV6RAServiceConfig } from "@/lib/icmpv6ra";
import { ServiceStatus } from "@/lib/services";
import axiosService from ".";

export async function get_all_icmpv6ra_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await axiosService.get(`services/icmpv6ra/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_iface_icmpv6ra_config(
  iface_name: string
): Promise<IPV6RAServiceConfig> {
  let data = await axiosService.get(`services/icmpv6ra/${iface_name}`);
  console.log(data.data);
  return data.data;
}

export async function update_icmpv6ra_config(
  icmpv6ra_config: IPV6RAServiceConfig
): Promise<void> {
  let data = await axiosService.post(`services/icmpv6ra`, {
    ...icmpv6ra_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_icmpv6ra(name: string): Promise<void> {
  return axiosService.delete(`services/icmpv6ra/${name}`);
}
