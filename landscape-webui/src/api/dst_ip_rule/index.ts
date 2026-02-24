import { WanIpRuleConfigClass } from "@/lib/mark";
import {
  getFlowDstIpRules,
  getDstIpRule,
  addDstIpRules,
  modifyDstIpRules,
  delDstIpRule,
  addManyDstIpRules,
} from "@landscape-router/types/api/destination-ip-rules/destination-ip-rules";
import type { WanIpRuleConfig } from "@landscape-router/types/api/schemas";

export async function get_flow_dst_ip_rules(
  flow_id: number,
): Promise<WanIpRuleConfig[]> {
  const data = await getFlowDstIpRules(flow_id);
  return data.map((d) => new WanIpRuleConfigClass(d));
}

export async function get_dst_ip_rules_rule(
  id: string,
): Promise<WanIpRuleConfig> {
  const data = await getDstIpRule(id);
  return new WanIpRuleConfigClass(data);
}

export async function push_dst_ip_rules_rule(
  rule: WanIpRuleConfig,
): Promise<void> {
  await addDstIpRules(rule);
}

export async function update_dst_ip_rules_rule(
  id: string,
  rule: WanIpRuleConfig,
): Promise<void> {
  await modifyDstIpRules(id, rule);
}

export async function delete_dst_ip_rules_rule(id: string): Promise<void> {
  await delDstIpRule(id);
}

export async function push_many_dst_ip_rule(
  rules: WanIpRuleConfig[],
): Promise<void> {
  await addManyDstIpRules(rules);
}
