import { MarkServiceConfig } from "@/lib/mark";
import { ServiceStatus } from "@/lib/services";
import axiosService from ".";

export async function get_all_mark_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await axiosService.get(`services/packet_marks/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  return map;
}

export async function get_iface_mark_config(
  iface_name: string
): Promise<MarkServiceConfig> {
  let data = await axiosService.get(`services/packet_marks/${iface_name}`);
  console.log(data.data);
  return data.data;
}

export async function update_iface_mark_config(
  mark_config: MarkServiceConfig
): Promise<void> {
  let data = await axiosService.post(`services/packet_marks`, {
    ...mark_config,
  });
  console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_mark(name: string): Promise<void> {
  return axiosService.delete(`services/packet_marks/${name}`);
}
