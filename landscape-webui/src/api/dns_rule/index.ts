import { DnsRule } from "@/lib/dns";
import {
  getFlowDnsRules,
  getDnsRule,
  addDnsRules,
  delDnsRules,
  addManyDnsRules,
} from "@landscape-router/types/api/dns-rules/dns-rules";

export async function get_flow_dns_rules(flow_id: number): Promise<DnsRule[]> {
  const data = await getFlowDnsRules(flow_id);
  return data.map((d) => new DnsRule(d));
}

export async function get_dns_rule(id: string): Promise<DnsRule> {
  const data = await getDnsRule(id);
  return new DnsRule(data);
}

export async function push_dns_rule(rule: DnsRule): Promise<void> {
  await addDnsRules(rule);
}

export async function delete_dns_rule(id: string): Promise<void> {
  await delDnsRules(id);
}

export async function push_many_dns_rule(rule: DnsRule[]): Promise<void> {
  await addManyDnsRules(rule);
}
