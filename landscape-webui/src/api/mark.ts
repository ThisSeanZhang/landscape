import axiosService from ".";
import { LanIPRuleConfig } from "@/lib/mark";

export async function get_lan_ip_rules(): Promise<LanIPRuleConfig[]> {
  let data = await axiosService.get(`global_mark/lans`);
  //   console.log(data.data);
  return data.data.map((e: any) => new LanIPRuleConfig(e));
}

export async function post_lan_ip_rules(data: LanIPRuleConfig): Promise<void> {
  let result = await axiosService.post(`global_mark/lans`, data);
  //   console.log(data.data);
}

export async function del_lan_ip_rules(index: number): Promise<void> {
  let result = await axiosService.delete(`global_mark/lans/${index}`);
  //   console.log(data.data);
}

// export async function get_wan_ip_rules(): Promise<WanIPRuleConfig[]> {
//   let data = await api.api.get(`global_mark/wans`);
//   //   console.log(data.data);
//   return data.data.map((e: any) => new WanIPRuleConfig(e));
// }

// export async function post_wan_ip_rules(data: WanIPRuleConfig): Promise<void> {
//   let result = await api.api.post(`global_mark/wans`, data);
//   //   console.log(data.data);
// }

// export async function del_wan_ip_rules(index: number): Promise<void> {
//   let result = await api.api.delete(`global_mark/wans/${index}`);
//   //   console.log(data.data);
// }
