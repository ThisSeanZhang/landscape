import axiosService from "@/api";
import { FirewallRule } from "@/lib/mark";
import { FirewallRuleConfig } from "@/rust_bindings/common/firewall";

export async function get_firewall_rules(): Promise<FirewallRuleConfig[]> {
  let data = await axiosService.get(`config/firewall_rules`);
  return data.data.map((d: any) => new FirewallRule(d));
}

export async function get_firewall_rule(
  id: string
): Promise<FirewallRuleConfig> {
  let data = await axiosService.get(`config/firewall_rules/${id}`);
  return new FirewallRule(data.data);
}

export async function push_firewall_rule(
  rule: FirewallRuleConfig
): Promise<void> {
  let data = await axiosService.post(`config/firewall_rules`, rule);
}

export async function delete_firewall_rule(id: string): Promise<void> {
  let data = await axiosService.delete(`config/firewall_rules/${id}`);
}
