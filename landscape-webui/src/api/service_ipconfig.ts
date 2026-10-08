import { getRuntimeIpAddresses } from "@landscape-router/types/api/ip-config/ip-config";
import type { RuntimeIpAddress } from "@landscape-router/types/api/schemas";

export type { RuntimeIpAddress };

export async function get_runtime_ip_addresses(
  iface_name: string,
): Promise<RuntimeIpAddress[]> {
  return (await getRuntimeIpAddresses(iface_name, { silent: true })) ?? [];
}
