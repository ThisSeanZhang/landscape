import axiosService from ".";
import { IpMacBinding } from "landscape-types/common/mac_binding";

export async function get_mac_bindings(): Promise<IpMacBinding[]> {
  let data = await axiosService.get(`config/mac_bindings`);
  return data.data;
}

export async function get_mac_binding_by_id(
  id: string,
): Promise<IpMacBinding | null> {
  let data = await axiosService.get(`config/mac_bindings/${id}`);
  return data.data;
}

export async function create_mac_binding(data: IpMacBinding): Promise<void> {
  return await axiosService.post(`config/mac_bindings`, data);
}

export async function update_mac_binding(
  id: string,
  data: IpMacBinding,
): Promise<void> {
  return await axiosService.put(`config/mac_bindings/${id}`, data);
}

export async function delete_mac_binding(id: string): Promise<void> {
  return await axiosService.delete(`config/mac_bindings/${id}`);
}

export async function validate_mac_binding_ip(
  iface_name: string,
  ipv4: string,
): Promise<boolean> {
  let data = await axiosService.post(`config/mac_bindings/validate_ip`, {
    iface_name,
    ipv4,
  });
  return data.data;
}
