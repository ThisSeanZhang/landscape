import { ServiceStatus } from "@/lib/services";
import type {
  ConnectKey,
  ConnectMetricPoint,
  ConnectRealtimeStatus,
  ConnectHistoryStatus,
  ConnectGlobalStats,
  IpRealtimeStat,
  IpHistoryStat,
  GetConnectHistoryParams as ConnectHistoryQueryParams,
  MetricResolution,
} from "landscape-types/api/schemas";
import {
  getSrcIpStats as _getSrcIpStats,
  getDstIpStats as _getDstIpStats,
  getConnectGlobalStats as _getConnectGlobalStats,
  getMetricStatus as _getMetricStatus,
  getConnectsInfo as _getConnectsInfo,
  getConnectHistory as _getConnectHistory,
  getConnectMetricInfo as _getConnectMetricInfo,
  getHistorySrcIpStats as _getHistorySrcIpStats,
  getHistoryDstIpStats as _getHistoryDstIpStats,
} from "landscape-types/api/metric/metric";

export * from "./dns";

export async function get_src_ip_stats(): Promise<IpRealtimeStat[]> {
  return _getSrcIpStats();
}

export async function get_dst_ip_stats(): Promise<IpRealtimeStat[]> {
  return _getDstIpStats();
}

export async function get_connect_global_stats(): Promise<ConnectGlobalStats> {
  return _getConnectGlobalStats();
}

export async function get_metric_status(): Promise<ServiceStatus> {
  return _getMetricStatus() as Promise<ServiceStatus>;
}

export async function get_connects_info(): Promise<ConnectRealtimeStatus[]> {
  return _getConnectsInfo();
}

export async function get_connect_history(
  params?: ConnectHistoryQueryParams,
): Promise<ConnectHistoryStatus[]> {
  return _getConnectHistory(params);
}

export async function get_connect_metric_info(
  key: ConnectKey,
  resolution?: MetricResolution,
): Promise<ConnectMetricPoint[]> {
  return _getConnectMetricInfo({ key, resolution });
}

export async function get_history_src_ip_stats(
  params?: ConnectHistoryQueryParams,
): Promise<IpHistoryStat[]> {
  return _getHistorySrcIpStats(params);
}

export async function get_history_dst_ip_stats(
  params?: ConnectHistoryQueryParams,
): Promise<IpHistoryStat[]> {
  return _getHistoryDstIpStats(params);
}
