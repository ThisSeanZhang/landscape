import api from "@/api";
import { WanIPRuleConfigClass } from "@/lib/mark";

import { WanIPRuleConfig } from "@/rust_bindings/flow";

export async function get_wan_ip_rules(
  flow_id: number
): Promise<WanIPRuleConfig[]> {
  let data = await api.api.get(`flow/${flow_id}/wans`);
  //   console.log(data.data);
  return data.data.map((e: any) => new WanIPRuleConfigClass(e));
}

export async function get_wan_ip_rule(
  flow_id: number,
  rule_id: string
): Promise<WanIPRuleConfig> {
  let data = await api.api.get(`flow/${flow_id}/wans/${rule_id}`);
  //   console.log(data.data);
  return new WanIPRuleConfigClass(data.data);
}

export async function post_wan_ip_rules(
  flow_id: number,
  data: WanIPRuleConfig
): Promise<void> {
  let result = await api.api.post(`flow/${flow_id}/wans`, data);
  //   console.log(data.data);
}

export async function update_wan_ip_rules(
  flow_id: number,
  rule_id: string,
  data: WanIPRuleConfig
): Promise<void> {
  let result = await api.api.put(`flow/${flow_id}/wans/${rule_id}`, data);
  //   console.log(data.data);
}

export async function del_wan_ip_rules(index: number): Promise<void> {
  let result = await api.api.delete(`flow/wans/${index}`);
  //   console.log(data.data);
}
