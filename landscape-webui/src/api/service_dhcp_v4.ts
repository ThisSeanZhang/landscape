import { DHCPv4ServiceConfig } from "@/lib/dhcp_v4";
import axiosService from ".";
import { ServiceStatus } from "@/lib/services";
import { DHCPv4OfferInfo } from "@/rust_bindings/common/dhcp_v4_server";

export async function get_all_dhcp_v4_status(): Promise<
  Map<string, ServiceStatus>
> {
  let data = await axiosService.get(`services/dhcp_v4/status`);
  let map = new Map<string, ServiceStatus>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, new ServiceStatus(value as any));
  }
  // console.log(map);
  return map;
}

export async function get_dhcp_v4_assigned_ips(): Promise<
  Map<string, DHCPv4OfferInfo | null>
> {
  let data = await axiosService.get(`services/dhcp_v4/assigned_ips`);
  let map = new Map<string, DHCPv4OfferInfo | null>();
  for (const [key, value] of Object.entries(data.data)) {
    map.set(key, value as DHCPv4OfferInfo);
  }
  return map;
}

export async function get_dhcp_v4_assigned_ips_by_iface_name(
  iface_name: string
): Promise<DHCPv4OfferInfo | null> {
  let data = await axiosService.get(
    `services/dhcp_v4/${iface_name}/assigned_ips`
  );
  return data.data;
}

export async function get_iface_dhcp_v4_config(
  iface_name: string
): Promise<DHCPv4ServiceConfig> {
  let data = await axiosService.get(`services/dhcp_v4/${iface_name}`);
  // console.log(data.data);
  return data.data;
}

export async function update_dhcp_v4_config(
  dhcp_v4_config: DHCPv4ServiceConfig
): Promise<void> {
  let data = await axiosService.post(`services/dhcp_v4`, {
    ...dhcp_v4_config,
  });
  // console.log(data.data);
  return data.data;
}

export async function stop_and_del_iface_dhcp_v4(name: string): Promise<void> {
  return axiosService.delete(`services/dhcp_v4/${name}`);
}
