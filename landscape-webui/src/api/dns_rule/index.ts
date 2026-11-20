import type { DNSRuleConfig } from "@landscape-router/types/api/schemas";
import { createDnsRule } from "@/lib/dns";
import {
  getFlowDnsRules,
  getDnsRule,
  addDnsRules,
  delDnsRules,
  addManyDnsRules,
} from "@landscape-router/types/api/dns-rules/dns-rules";

export async function get_flow_dns_rules(
  flow_id: number,
): Promise<DNSRuleConfig[]> {
  const data = await getFlowDnsRules(flow_id);
  return data.map((d) => createDnsRule(d));
}

export async function get_dns_rule(id: string): Promise<DNSRuleConfig> {
  const data = await getDnsRule(id);
  return createDnsRule(data);
}

export async function push_dns_rule(rule: DNSRuleConfig): Promise<void> {
  await addDnsRules(rule);
}

export async function delete_dns_rule(id: string): Promise<void> {
  await delDnsRules(id);
}

export async function push_many_dns_rule(rule: DNSRuleConfig[]): Promise<void> {
  await addManyDnsRules(rule);
}
