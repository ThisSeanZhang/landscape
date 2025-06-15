import axiosService from "@/api";
import { DnsRule } from "@/lib/dns";

export async function get_flow_dns_rules(flow_id: number): Promise<DnsRule[]> {
  let data = await axiosService.get(`config/dns_rules/flow/${flow_id}`);
  return data.data.map((d: any) => new DnsRule(d));
}

export async function get_dns_rule(id: string): Promise<DnsRule> {
  let data = await axiosService.get(`config/dns_rules/${id}`);
  return new DnsRule(data.data);
}

export async function push_dns_rule(rule: DnsRule): Promise<void> {
  let data = await axiosService.post(`config/dns_rules`, rule);
}

export async function delete_dns_rule(id: string): Promise<void> {
  let data = await axiosService.delete(`config/dns_rules/${id}`);
}

export async function push_many_dns_rule(rule: DnsRule[]): Promise<void> {
  let data = await axiosService.post(`config/dns_rules/set_many`, rule);
}
