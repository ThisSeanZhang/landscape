import {
  getDnsUpstreams,
  getDnsUpstream,
  addDnsUpstream,
  delDnsUpstream,
  addManyDnsUpstreams,
} from "landscape-types/api/dns-upstreams/dns-upstreams";
import type { DnsUpstreamConfig } from "landscape-types/api/schemas";

export async function get_dns_upstreams(): Promise<DnsUpstreamConfig[]> {
  return getDnsUpstreams();
}

export async function get_dns_upstream(id: string): Promise<DnsUpstreamConfig> {
  return getDnsUpstream(id);
}

export async function push_dns_upstream(
  rule: DnsUpstreamConfig,
): Promise<void> {
  await addDnsUpstream(rule);
}

export async function delete_dns_upstream(id: string): Promise<void> {
  await delDnsUpstream(id);
}

export async function push_many_dns_upstream(
  rule: DnsUpstreamConfig[],
): Promise<void> {
  await addManyDnsUpstreams(rule);
}
