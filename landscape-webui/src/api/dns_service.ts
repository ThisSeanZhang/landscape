import { CheckDnsReq, CheckDnsResult } from "@/rust_bindings/dns";
import axiosService from ".";
import { ServiceStatus } from "@/lib/services";

export async function get_dns_status(): Promise<ServiceStatus> {
  let data = await axiosService.get("sys_service/dns");
  // console.log(data.data);
  return new ServiceStatus(data.data);
}

export async function start_dns_service(
  udp_port: number
): Promise<ServiceStatus> {
  let data = await axiosService.post("sys_service/dns", {
    udp_port,
  });
  // console.log(data.data);
  return new ServiceStatus(data.data.status);
}

export async function stop_dns_service(): Promise<ServiceStatus> {
  let data = await axiosService.delete("sys_service/dns");
  // console.log(data.data);
  return new ServiceStatus(data.data.status);
}

export async function check_domain(req: CheckDnsReq): Promise<CheckDnsResult> {
  let data = await axiosService.get("sys_service/dns/check", {
    params: { ...req },
  });
  return data.data;
}
