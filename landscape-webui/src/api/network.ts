import { IpConfigMode, NetworkConfig } from "@lib/network_config";
import { NetDev, WifiMode } from "@/lib/dev";
import { IfaceZoneType } from "@/rust_bindings/common/iface";
import axiosService from "../api";

export async function ifaces(): Promise<NetDev[]> {
  let data = await axiosService.get("iface");
  // console.log(data.data);
  return data.data.map((e: any) => new NetDev(e));
}

export async function ifaces_by_name(name: string): Promise<NetworkConfig> {
  let data = await axiosService.get(`iface/${name}`);
  // console.log(data.data);
  return data.data;
}

export async function update_iface_ip_mode(
  name: string,
  data: IpConfigMode
): Promise<NetworkConfig> {
  let result = await axiosService.post(`iface/${name}/ip_config_mode`, data);
  // console.log(result.data);
  return result.data;
}

export async function add_controller(data: {
  link_name: string;
  link_ifindex: number;
  master_name: string | undefined;
  master_ifindex: number | undefined;
}): Promise<any> {
  let result = await axiosService.post("iface/controller", data);
  return result.data;
}

export async function create_bridge(name: string): Promise<any> {
  let data = await axiosService.post("iface/bridge", {
    name,
  });
  // console.log(data.data);
  return data.data;
}

export async function change_zone(data: {
  iface_name: string;
  zone: IfaceZoneType;
}): Promise<any> {
  let result = await axiosService.post("iface/zone", data);
  return result.data;
}

export async function change_iface_status(
  iface_name: string,
  status: boolean
): Promise<any> {
  let result = await axiosService.post(`iface/${iface_name}/status/${status}`);
  return result.data;
}

export async function change_wifi_mode(
  iface_name: string,
  mode: WifiMode
): Promise<any> {
  let result = await axiosService.post(`iface/${iface_name}/wifi_mode/${mode}`);
  return result.data;
}
