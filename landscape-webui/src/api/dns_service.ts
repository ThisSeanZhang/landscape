import type {
  CheckChainDnsResult,
  CheckDomainParams,
} from "@landscape-router/types/api/schemas";
import {
  startDnsService,
  stopDnsService,
  checkDomain,
  invalidateDomainCache,
  refreshDomainCache,
} from "@landscape-router/types/api/dns-service/dns-service";

export async function start_dns_service(): Promise<void> {
  await startDnsService();
}

export async function stop_dns_service(): Promise<void> {
  await stopDnsService();
}

export async function check_domain(
  req: CheckDomainParams,
): Promise<CheckChainDnsResult> {
  return await checkDomain(req);
}

export async function invalidate_domain_cache(
  req: CheckDomainParams,
): Promise<CheckChainDnsResult> {
  return await invalidateDomainCache(req);
}

export async function refresh_domain_cache(
  req: CheckDomainParams,
): Promise<CheckChainDnsResult> {
  return await refreshDomainCache(req);
}
