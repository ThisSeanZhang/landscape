import { FlowMark } from "@/rust_bindings/flow";
import { FlowMarkType } from "./default_value";
import {
  DNSResolveMode,
  DNSRuleConfig,
  FilterResult,
  RuleSource,
} from "@/rust_bindings/common/dns";

export enum DnsUpstreamModeTsEnum {
  Plaintext = "plaintext",
  Tls = "tls",
  Https = "https",
  Quic = "quic",
}

export const UPSTREAM_OPTIONS = [
  {
    label: "UDP",
    value: DnsUpstreamModeTsEnum.Plaintext,
  },
  {
    label: "DoH",
    value: DnsUpstreamModeTsEnum.Https,
  },
  {
    label: "DoT",
    value: DnsUpstreamModeTsEnum.Tls,
  },
  {
    label: "DoQ",
    value: DnsUpstreamModeTsEnum.Quic,
  },
];

export function upstream_mode_exhibit_name(mode: string): string {
  for (const each of UPSTREAM_OPTIONS) {
    if (each.value === mode) {
      return each.label;
    }
  }
  return mode;
}

export function convert_flow_mark(flow_mark?: FlowMark): FlowMark {
  if (flow_mark) {
    return flow_mark;
  } else {
    return {
      action: { t: FlowMarkType.KeepGoing },
      flow_id: 0,
      allow_reuse_port: false,
    };
  }
}

export class DnsRule implements DNSRuleConfig {
  id?: string;
  index: number;
  name: string;
  enable: boolean;
  mark: FlowMark;
  source: RuleSource[];
  resolve_mode: DNSResolveMode;
  flow_id: number;
  filter: FilterResult;
  update_at?: number;
  upstream_id: string;

  constructor(obj?: Partial<DNSRuleConfig>) {
    this.id = obj?.id;
    this.index = obj?.index ?? -1;
    this.name = obj?.name ?? "";
    this.enable = obj?.enable ?? true;
    this.mark = convert_flow_mark(obj?.mark);
    this.source = obj?.source ?? [];
    this.resolve_mode = obj?.resolve_mode
      ? { ...obj.resolve_mode }
      : {
          t: DNSResolveModeEnum.Cloudflare,
          mode: CloudflareMode.Https,
        };
    this.flow_id = obj?.flow_id ?? 0;
    this.filter = obj?.filter ?? "unfilter";
    this.update_at = obj?.update_at;
    this.upstream_id = obj?.upstream_id ?? "";
  }
}

export enum DomainMatchTypeEnum {
  Plain = "plain",
  Regex = "regex",
  Domain = "domain",
  Full = "full",
}

export enum RuleSourceEnum {
  GeoKey = "geo_key",
  Config = "config",
}

// export type RuleSource =
//   | { t: "geokey"; key: string }
//   | { t: "config"; match_type: DomainMatchType; value: string };

export enum MarkType {
  NoMark = "nomark",
  /// 直连
  Direct = "direct",
  /// 丢弃数据包
  Drop = "drop",
  /// 转发到另一张网卡中
  Redirect = "redirect",
  /// 进行 IP 校验 ( 阻止进行打洞 )
  SymmetricNat = "symmetricnat",
  RedirectNetns = "redirectnetns",
}

export type PacketMark =
  | { t: MarkType.NoMark }
  | { t: MarkType.Direct }
  | { t: MarkType.Drop }
  | { t: MarkType.Redirect; index: number }
  | { t: MarkType.SymmetricNat }
  | { t: MarkType.RedirectNetns; index: number };

export function get_dns_filter_options(): {
  label: string;
  value: string;
}[] {
  return [
    { label: "不过滤", value: FilterResultEnum.Unfilter },
    { label: "仅 IPv4", value: FilterResultEnum.OnlyIPv4 },
    { label: "仅 IPv6", value: FilterResultEnum.OnlyIPv6 },
  ];
}

export function get_dns_resolve_mode_options(): {
  label: string;
  value: string;
}[] {
  return [
    { label: "重定向", value: DNSResolveModeEnum.Redirect },
    { label: "自定义上游", value: DNSResolveModeEnum.Upstream },
    { label: "Cloudflare", value: DNSResolveModeEnum.Cloudflare },
  ];
}

export function get_dns_upstream_type_options(): {
  label: string;
  value: string;
}[] {
  return [
    { label: "无加密", value: DnsUpstreamTypeEnum.Plaintext },
    { label: "TLS", value: DnsUpstreamTypeEnum.Tls },
    { label: "HTTPS", value: DnsUpstreamTypeEnum.Https },
  ];
}

export enum DNSResolveModeEnum {
  Redirect = "redirect",
  Upstream = "upstream",
  Cloudflare = "cloudflare",
}

export enum DnsUpstreamTypeEnum {
  Plaintext = "plaintext",
  Tls = "tls",
  Https = "https",
}

export enum CloudflareMode {
  Plaintext = "plaintext",
  Tls = "tls",
  Https = "https",
}

export type DnsUpstreamType =
  | { t: DnsUpstreamTypeEnum.Plaintext }
  | { t: DnsUpstreamTypeEnum.Tls; domain: string }
  | { t: DnsUpstreamTypeEnum.Https; domain: string };

// export type DNSResolveMode =
//   | { t: DNSResolveModeEnum.Redirect; ips: string[] }
//   | DnsUpstreamMode
//   | { t: DNSResolveModeEnum.Cloudflare; mode: CloudFlareMode };

export type DnsUpstreamMode = {
  t: DNSResolveModeEnum.Upstream;
  upstream: DnsUpstreamType;
  ips: string[];
  port?: number;
};

export enum FilterResultEnum {
  Unfilter = "unfilter",
  OnlyIPv4 = "only_ipv4",
  OnlyIPv6 = "only_ipv6",
}
