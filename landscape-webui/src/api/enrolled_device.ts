import axiosService from ".";
import { EnrolledDevice } from "landscape-types/common/enrolled_device";

export async function get_enrolled_devices(): Promise<EnrolledDevice[]> {
  let data = await axiosService.get(`config/enrolled_devices`);
  return data.data;
}

export async function get_enrolled_device_by_id(
  id: string,
): Promise<EnrolledDevice | null> {
  let data = await axiosService.get(`config/enrolled_devices/${id}`);
  return data.data;
}

export async function create_enrolled_device(
  data: EnrolledDevice,
): Promise<void> {
  return await axiosService.post(`config/enrolled_devices`, data);
}

export async function update_enrolled_device(
  id: string,
  data: EnrolledDevice,
): Promise<void> {
  return await axiosService.put(`config/enrolled_devices/${id}`, data);
}

export async function delete_enrolled_device(id: string): Promise<void> {
  return await axiosService.delete(`config/enrolled_devices/${id}`);
}

export async function validate_enrolled_device_ip(
  iface_name: string,
  ipv4: string,
): Promise<boolean> {
  let data = await axiosService.post(`config/enrolled_devices/validate_ip`, {
    iface_name,
    ipv4,
  });
  return data.data;
}

export async function check_iface_enrolled_devices_validity(
  iface_name: string,
): Promise<EnrolledDevice[]> {
  let data = await axiosService.get(
    `config/enrolled_devices/check_invalid/${iface_name}`,
  );
  return data.data;
}
