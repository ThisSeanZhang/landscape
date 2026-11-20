import type { LandscapeApiOptions } from "@landscape-router/types/mutator";
import type {
  DnsHistoryResponse,
  DnsSummaryResponse,
  DnsLightweightSummaryResponse,
  GetDnsHistoryParams,
  GetDnsSummaryParams,
  GetDnsLightweightSummaryParams,
} from "@landscape-router/types/api/schemas";
import {
  getDnsHistory as _getDnsHistory,
  getDnsSummary as _getDnsSummary,
  getDnsLightweightSummary as _getDnsLightweightSummary,
} from "@landscape-router/types/api/metric/metric";

export async function get_dns_history(
  params: GetDnsHistoryParams = {},
  options?: LandscapeApiOptions,
): Promise<DnsHistoryResponse> {
  return _getDnsHistory(params, options);
}

export async function get_dns_summary(
  params: GetDnsSummaryParams,
  options?: LandscapeApiOptions,
): Promise<DnsSummaryResponse> {
  return _getDnsSummary(params, options);
}

export async function get_dns_lightweight_summary(
  params: GetDnsLightweightSummaryParams,
): Promise<DnsLightweightSummaryResponse> {
  return _getDnsLightweightSummary(params);
}

export { getDnsLiveDashboard } from "@landscape-router/types/api/metric/metric";
