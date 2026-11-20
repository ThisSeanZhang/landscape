import {
  getAllIpv6pdPrefixStatus,
  getCurrentIpPrefixInfo,
} from "@landscape-router/types/api/ipv6-pd/ipv6-pd";
import type {
  IPV6PDPrefixStatus,
  LDIAPrefix,
} from "@landscape-router/types/api/schemas";

export async function get_current_ip_prefix_info(): Promise<
  Map<string, LDIAPrefix | null>
> {
  const data = await getCurrentIpPrefixInfo();
  return new Map(Object.entries(data));
}

export async function get_all_ipv6pd_prefix_status(): Promise<
  Map<string, IPV6PDPrefixStatus>
> {
  const data = await getAllIpv6pdPrefixStatus();
  return new Map(Object.entries(data));
}
