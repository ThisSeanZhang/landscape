import { DhcpServerConfig } from "./dhcp";
import { ServiceStatus } from "./services";

export enum ZoneType {
  Undefined = "undefined",
  Lan = "lan",
  Wan = "wan",
}
// 准备移除
export enum IfaceServiceType {
  Undefined = "undefined",
  Lan = "lan",
  Wan = "wan",
}

export type WanIpConfigMode =
  | { t: "nothing" }
  | { t: "static"; ipv4: number[]; ipv4_mask: number; ipv6: number[] }
  | { t: "pppoe"; username: string; password: string; mtu: number }
  | { t: "dhcpclient" };

export type LanIpConfigMode =
  | { t: "nothing" }
  | { t: "static"; ipv4: number[]; ipv4_mask: number; ipv6: number[] }
  | DhcpServerConfig;

export type IfaceServiceConfig =
  | { t: IfaceServiceType.Undefined }
  | {
      t: IfaceServiceType.Lan;
      ip_config_enable: boolean;
      ip_config_mode: LanIpConfigMode;
    }
  | {
      t: IfaceServiceType.Wan;
      ip_config_enable: boolean;
      ip_config_mode: WanIpConfigMode;
    };

export type IfaceServiceStatus =
  | { t: IfaceServiceType.Undefined }
  | { t: IfaceServiceType.Wan; ip_config_status: ServiceStatus };

export enum IfaceIpMode {
  Nothing = "nothing",
  Static = "static",
  PPPoE = "pppoe",
  DHCPServer = "dhcpserver",
  DHCPClient = "dhcpclient",
}
export type IfaceIpModelConfig =
  | { t: "nothing" }
  | { t: "static"; ipv4: number[]; ipv4_mask: number; ipv6: number[] }
  | { t: "pppoe"; username: string; password: string; mtu: number }
  | DhcpServerConfig
  | { t: "dhcpclient" };

export class IfaceIpServiceConfig {
  iface_name: string;
  enable: boolean;
  ip_model: IfaceIpModelConfig;

  constructor(obj?: {
    iface_name?: string;
    enable?: boolean;
    ip_model?: IfaceIpModelConfig;
  }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
    this.ip_model = obj?.ip_model ?? { t: "nothing" };
  }
}

export class StaticIpConfig {
  t: IfaceIpMode.Static;
  ipv4: number[];
  ipv4_mask: number;
  ipv6: number[];

  constructor(obj?: {
    ipv4?: [number, number, number, number];
    ipv4_mask?: number;
    ipv6?: number[];
  }) {
    this.t = IfaceIpMode.Static;
    this.ipv4 = obj?.ipv4 ?? [1, 1, 1, 1];
    this.ipv4_mask = obj?.ipv4_mask ?? 24;
    this.ipv6 = obj?.ipv6 ?? [];
  }
}
