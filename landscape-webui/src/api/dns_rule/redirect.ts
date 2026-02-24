import {
  getDnsRedirects,
  getDnsRedirect,
  addDnsRedirects,
  delDnsRedirects,
  addManyDnsRedirects,
} from "landscape-types/api/dns-redirects/dns-redirects";
import type { DNSRedirectRule } from "landscape-types/api/schemas";

export async function get_dns_redirects(): Promise<DNSRedirectRule[]> {
  return getDnsRedirects();
}

export async function get_dns_redirect(id: string): Promise<DNSRedirectRule> {
  return getDnsRedirect(id);
}

export async function push_dns_redirect(rule: DNSRedirectRule): Promise<void> {
  await addDnsRedirects(rule);
}

export async function delete_dns_redirect(id: string): Promise<void> {
  await delDnsRedirects(id);
}

export async function push_many_dns_redirect(
  rule: DNSRedirectRule[],
): Promise<void> {
  await addManyDnsRedirects(rule);
}
