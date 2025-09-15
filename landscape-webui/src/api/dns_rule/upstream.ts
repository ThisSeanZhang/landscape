import axiosService from "@/api";
import { DnsUpstreamConfig } from "@/rust_bindings/common/dns";

export async function get_dns_upstreams(): Promise<DnsUpstreamConfig[]> {
  let data = await axiosService.get(`config/dns_upstreams`);
  return data.data;
}

export async function get_dns_upstream(id: string): Promise<DnsUpstreamConfig> {
  let data = await axiosService.get(`config/dns_upstreams/${id}`);
  return data.data;
}

export async function push_dns_upstream(
  rule: DnsUpstreamConfig
): Promise<void> {
  let data = await axiosService.post(`config/dns_upstreams`, rule);
}

export async function delete_dns_upstream(id: string): Promise<void> {
  let data = await axiosService.delete(`config/dns_upstreams/${id}`);
}

export async function push_many_dns_upstream(
  rule: DnsUpstreamConfig[]
): Promise<void> {
  let data = await axiosService.post(`config/dns_upstreams/set_many`, rule);
}
