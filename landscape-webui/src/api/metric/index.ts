import axiosService from "@/api";
import { ServiceStatus } from "@/lib/services";
import {
  ConnectKey,
  ConnectMetric,
  ConnectRealtimeStatus,
  ConnectHistoryStatus,
  ConnectGlobalStats,
  ConnectHistoryQueryParams,
  IpRealtimeStat,
  IpHistoryStat,
  MetricResolution,
} from "landscape-types/common/metric/connect";

export * from "./dns";

export async function get_src_ip_stats(): Promise<IpRealtimeStat[]> {
  let data = await axiosService.get("metric/connects/src_ip_stats");
  return data.data;
}

export async function get_dst_ip_stats(): Promise<IpRealtimeStat[]> {
  let data = await axiosService.get("metric/connects/dst_ip_stats");
  return data.data;
}

export async function get_connect_global_stats(): Promise<ConnectGlobalStats> {
  let data = await axiosService.get("metric/connects/global_stats");
  return data.data;
}

export async function get_metric_status(): Promise<ServiceStatus> {
  let data = await axiosService.get("metric/status");
  return data.data;
}

export async function get_connects_info(): Promise<ConnectRealtimeStatus[]> {
  let data = await axiosService.get("metric/connects");
  return data.data;
}

export async function get_connect_history(
  params?: ConnectHistoryQueryParams,
): Promise<ConnectHistoryStatus[]> {
  let data = await axiosService.get("metric/connects/history", {
    params,
  });
  return data.data;
}

export async function get_connect_metric_info(
  key: ConnectKey,
  resolution?: MetricResolution,
): Promise<ConnectMetric[]> {
  let data = await axiosService.post("metric/connects/chart", {
    key,
    resolution,
  });
  return data.data;
}

export async function get_history_src_ip_stats(
  params?: ConnectHistoryQueryParams,
): Promise<IpHistoryStat[]> {
  let data = await axiosService.get("metric/connects/history/src_ip_stats", {
    params,
  });
  return data.data;
}

export async function get_history_dst_ip_stats(
  params?: ConnectHistoryQueryParams,
): Promise<IpHistoryStat[]> {
  let data = await axiosService.get("metric/connects/history/dst_ip_stats", {
    params,
  });
  return data.data;
}
