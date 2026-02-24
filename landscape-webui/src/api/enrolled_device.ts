import {
  listEnrolledDevices,
  getEnrolledDevice,
  pushEnrolledDevice,
  updateEnrolledDevice,
  deleteEnrolledDevice,
  handleValidateIp,
  checkIfaceValidity,
} from "landscape-types/api/enrolled-devices/enrolled-devices";
import type { EnrolledDevice } from "landscape-types/api/schemas";

export async function get_enrolled_devices(): Promise<EnrolledDevice[]> {
  return listEnrolledDevices();
}

export async function get_enrolled_device_by_id(
  id: string,
): Promise<EnrolledDevice | null> {
  return getEnrolledDevice(id);
}

export async function create_enrolled_device(
  data: EnrolledDevice,
): Promise<void> {
  await pushEnrolledDevice(data);
}

export async function update_enrolled_device(
  id: string,
  data: EnrolledDevice,
): Promise<void> {
  await updateEnrolledDevice(id, data);
}

export async function delete_enrolled_device(id: string): Promise<void> {
  await deleteEnrolledDevice(id);
}

export async function validate_enrolled_device_ip(
  iface_name: string,
  ipv4: string,
): Promise<boolean> {
  return handleValidateIp({ iface_name, ipv4 });
}

export async function check_iface_enrolled_devices_validity(
  iface_name: string,
): Promise<EnrolledDevice[]> {
  return checkIfaceValidity(iface_name);
}
