import type {
  CheckChainDnsResult,
  CheckDomainParams,
} from "landscape-types/api/schemas";
import {
  getDnsServiceStatus,
  startDnsService,
  stopDnsService,
  checkDomain,
} from "landscape-types/api/dns-service/dns-service";
import type { ServiceStatus } from "@/lib/services";

export async function get_dns_status(): Promise<ServiceStatus> {
  const data = await getDnsServiceStatus();
  return data as ServiceStatus;
}

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
