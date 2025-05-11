import { IpConfigMode, NetworkConfig } from "@lib/network_config";
import api from "../api";
import { ZoneType } from "@/lib/service_ipconfig";
import { NetDev, WifiMode } from "@/lib/dev";
import { IfaceZoneType } from "@/rust_bindings/common/iface";

export async function ifaces(): Promise<NetDev[]> {
  let data = await api.api.get("iface");
  // console.log(data.data);
  return data.data.map((e: any) => new NetDev(e));
}

export async function ifaces_by_name(name: string): Promise<NetworkConfig> {
  let data = await api.api.get(`iface/${name}`);
  // console.log(data.data);
  return data.data;
}

export async function update_iface_ip_mode(
  name: string,
  data: IpConfigMode
): Promise<NetworkConfig> {
  let result = await api.api.post(`iface/${name}/ip_config_mode`, data);
  // console.log(result.data);
  return result.data;
}

export async function add_controller(data: {
  link_name: string;
  link_ifindex: number;
  master_name: string | undefined;
  master_ifindex: number | undefined;
}): Promise<any> {
  let result = await api.api.post("iface/controller", data);
  return result.data;
}

export async function create_bridge(name: string): Promise<any> {
  let data = await api.api.post("iface/bridge", {
    name,
  });
  // console.log(data.data);
  return data.data;
}

export async function change_zone(data: {
  iface_name: string;
  zone: IfaceZoneType;
}): Promise<any> {
  let result = await api.api.post("iface/zone", data);
  return result.data;
}

export async function change_iface_status(
  iface_name: string,
  status: boolean
): Promise<any> {
  let result = await api.api.post(`iface/${iface_name}/status/${status}`);
  return result.data;
}

export async function change_wifi_mode(
  iface_name: string,
  mode: WifiMode
): Promise<any> {
  let result = await api.api.post(`iface/${iface_name}/wifi_mode/${mode}`);
  return result.data;
}
