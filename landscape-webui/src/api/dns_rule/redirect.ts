import axiosService from "@/api";
import { DNSRedirectRule } from "@/rust_bindings/common/dns_redirect";

export async function get_dns_redirects(): Promise<DNSRedirectRule[]> {
  let data = await axiosService.get(`config/dns_redirects`);
  return data.data;
}

export async function get_dns_redirect(id: string): Promise<DNSRedirectRule> {
  let data = await axiosService.get(`config/dns_redirects/${id}`);
  return data.data;
}

export async function push_dns_redirect(rule: DNSRedirectRule): Promise<void> {
  let data = await axiosService.post(`config/dns_redirects`, rule);
}

export async function delete_dns_redirect(id: string): Promise<void> {
  let data = await axiosService.delete(`config/dns_redirects/${id}`);
}

export async function push_many_dns_redirect(
  rule: DNSRedirectRule[]
): Promise<void> {
  let data = await axiosService.post(`config/dns_redirects/set_many`, rule);
}
