import {
  getFirewallBlacklists,
  getFirewallBlacklist,
  addFirewallBlacklist,
  delFirewallBlacklist,
} from "@landscape-router/types/api/firewall-blacklists/firewall-blacklists";
import type { FirewallBlacklistConfig } from "@landscape-router/types/api/schemas";

export async function get_firewall_blacklists(): Promise<
  FirewallBlacklistConfig[]
> {
  return getFirewallBlacklists();
}

export async function get_firewall_blacklist(
  id: string,
): Promise<FirewallBlacklistConfig> {
  return getFirewallBlacklist(id);
}

export async function push_firewall_blacklist(
  config: FirewallBlacklistConfig,
): Promise<void> {
  await addFirewallBlacklist(config);
}

export async function delete_firewall_blacklist(id: string): Promise<void> {
  await delFirewallBlacklist(id);
}
