import type {
  ServiceStatus,
  ApiLanIPv6ServiceConfigV2 as LanIPv6ServiceConfigV2,
} from "@landscape-router/types/api/schemas";

import {
  getAllLanIpv6Configs,
  getAllLanIpv6Status,
  getLanIpv6Config,
  handleLanIpv6,
  deleteAndStopLanIpv6,
} from "@landscape-router/types/api/lan-ipv6/lan-ipv6";

export async function get_all_lan_ipv6_status(): Promise<
  Map<string, ServiceStatus>
> {
  const data = await getAllLanIpv6Status();
  return new Map(Object.entries(data));
}

export async function get_lan_ipv6_config(
  iface_name: string,
): Promise<LanIPv6ServiceConfigV2> {
  return await getLanIpv6Config(iface_name);
}

export async function get_all_lan_ipv6_configs(): Promise<
  LanIPv6ServiceConfigV2[]
> {
  return await getAllLanIpv6Configs();
}

export async function update_lan_ipv6_config(
  config: LanIPv6ServiceConfigV2,
): Promise<void> {
  await handleLanIpv6(config);
}

export async function stop_and_del_lan_ipv6(name: string): Promise<void> {
  await deleteAndStopLanIpv6(name);
}
