import { FirewallRule } from "@/lib/mark";
import {
  getFirewallRules,
  getFirewallRule,
  addFirewallRule,
  delFirewallRule,
} from "landscape-types/api/firewall-rules/firewall-rules";
import type { FirewallRuleConfig } from "landscape-types/api/schemas";

export async function get_firewall_rules(): Promise<FirewallRuleConfig[]> {
  const data = await getFirewallRules();
  return data.map((d) => new FirewallRule(d));
}

export async function get_firewall_rule(
  id: string,
): Promise<FirewallRuleConfig> {
  const data = await getFirewallRule(id);
  return new FirewallRule(data);
}

export async function push_firewall_rule(
  rule: FirewallRuleConfig,
): Promise<void> {
  await addFirewallRule(rule);
}

export async function delete_firewall_rule(id: string): Promise<void> {
  await delFirewallRule(id);
}
