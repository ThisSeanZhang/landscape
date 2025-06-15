import axiosService from "@/api";
import { ServiceStatus } from "@/lib/services";
import { FrontEndFirewallMetricServiceData } from "@/rust_bindings/common/metric";

export async function get_metric_status(): Promise<ServiceStatus> {
  let data = await axiosService.get("metric/status");
  // console.log(data.data);
  return data.data;
}

export async function get_firewall_metric_status(): Promise<FrontEndFirewallMetricServiceData> {
  let data = await axiosService.get("metric/firewall");
  // console.log(data.data);
  return data.data;
}
