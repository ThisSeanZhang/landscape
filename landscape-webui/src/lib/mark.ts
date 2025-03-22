import { MarkType, PacketMark } from "./dns";

export class MarkServiceConfig {
  iface_name: string;
  enable: boolean;

  constructor(obj: { iface_name: string; enable?: boolean }) {
    this.iface_name = obj?.iface_name ?? "";
    this.enable = obj?.enable ?? true;
  }
}

export class IpConfig {
  ip: string;
  prefix: number;

  constructor(obj?: { ip?: string; prefix?: number }) {
    this.ip = obj?.ip ?? "0.0.0.0";
    this.prefix = obj?.prefix ?? 32;
  }
}

export class LanIPRuleConfig {
  index: number;
  enable: boolean;
  mark: PacketMark;
  source: IpConfig[];
  remark: string;

  constructor(obj?: {
    index?: number;
    enable?: boolean;
    mark?: PacketMark;
    source?: IpConfig[];
    remark?: string;
  }) {
    this.index = obj?.index ?? -1;
    this.enable = obj?.enable ?? true;
    this.mark = obj?.mark ? { ...obj.mark } : { t: MarkType.NoMark };
    this.source = obj?.source ? obj?.source.map((e) => new IpConfig(e)) : [];
    this.remark = obj?.remark ?? "";
  }
}

export class WanIPRuleConfig {
  index: number;
  enable: boolean;
  mark: PacketMark;
  source: WanIPRuleSource[];
  remark: string;

  constructor(obj?: {
    index?: number;
    enable?: boolean;
    mark?: PacketMark;
    source?: WanIPRuleSource[];
    remark?: string;
  }) {
    this.index = obj?.index ?? -1;
    this.enable = obj?.enable ?? true;
    this.mark = obj?.mark ? { ...obj.mark } : { t: MarkType.NoMark };
    this.source = obj?.source ? obj?.source.map(new_wan_rules) : [];
    this.remark = obj?.remark ?? "";
  }
}

export type WanIPRuleSource =
  | { t: "geokey"; key: string }
  | { t: "config"; ip: string; prefix: number };

export function new_wan_rules(e: any): WanIPRuleSource {
  if (e.t == "config") {
    return { t: "config", ip: e.ip, prefix: e.prefix };
  } else {
    return { t: "geokey", key: e.key };
  }
}

export enum IPProtocol {
  ICMPV6 = "icmpv6",
  ICMP = "icmp",
  TCP = "tcp",
  UDP = "udp",
}

export class FirewallRuleConfig {
  index: number;
  enable: boolean;
  mark: PacketMark;
  items: FirewallRuleItem[];
  remark: string;

  constructor(obj?: {
    index?: number;
    enable?: boolean;
    mark?: PacketMark;
    items?: FirewallRuleItem[];
    remark?: string;
  }) {
    this.index = obj?.index ?? -1;
    this.enable = obj?.enable ?? true;
    this.mark = obj?.mark ? { ...obj.mark } : { t: MarkType.NoMark };
    this.items = obj?.items
      ? obj?.items.map((e) => new FirewallRuleItem(e))
      : [];
    this.remark = obj?.remark ?? "";
  }
}

export class FirewallRuleItem {
  ip_protocol: IPProtocol;
  local_port: number | undefined;
  address: string | undefined;
  ip_prefixlen: number;

  constructor(obj?: {
    ip_protocol?: IPProtocol;
    local_port?: number | undefined;
    address?: string | undefined;
    ip_prefixlen?: number;
  }) {
    this.ip_protocol = obj?.ip_protocol ?? IPProtocol.TCP;
    this.local_port = obj?.local_port ?? 80;
    this.address = obj?.address ?? "0.0.0.0";
    this.ip_prefixlen = obj?.ip_prefixlen ?? 0;
  }
}

export function protocol_options(): { label: string; value: string }[] {
  return [
    {
      label: "TCP",
      value: IPProtocol.TCP,
    },
    {
      label: "UDP",
      value: IPProtocol.UDP,
    },
    {
      label: "ICMP",
      value: IPProtocol.ICMP,
    },
    {
      label: "ICMPV6",
      value: IPProtocol.ICMPV6,
    },
  ];
}
