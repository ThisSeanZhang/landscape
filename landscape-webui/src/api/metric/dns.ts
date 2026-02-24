import type {
  DnsMetric,
  DnsHistoryResponse,
  DnsStatEntry,
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

export type {
  DnsMetric,
  DnsHistoryResponse,
  DnsStatEntry,
  DnsSummaryResponse,
  DnsLightweightSummaryResponse,
};

export async function get_dns_history(
  params: GetDnsHistoryParams = {},
): Promise<DnsHistoryResponse> {
  return _getDnsHistory(params);
}

export async function get_dns_summary(
  params: GetDnsSummaryParams,
): Promise<DnsSummaryResponse> {
  return _getDnsSummary(params);
}

export async function get_dns_lightweight_summary(
  params: GetDnsLightweightSummaryParams,
): Promise<DnsLightweightSummaryResponse> {
  return _getDnsLightweightSummary(params);
}
