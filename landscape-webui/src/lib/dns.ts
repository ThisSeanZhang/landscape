import { FlowDnsMark } from "@/rust_bindings/flow";
import { FlowDnsMarkType } from "./default_value";
import {
  DNSResolveMode,
  DNSRuleConfig,
  FilterResult,
  RuleSource,
} from "@/rust_bindings/common/dns";

export class DnsRule implements DNSRuleConfig {
  id: string | null;
  index: number;
  name: string;
  enable: boolean;
  mark: FlowDnsMark;
  source: RuleSource[];
  resolve_mode: DNSResolveMode;
  flow_id: number;
  filter: FilterResult;
  update_at: number;

  constructor(obj?: Partial<DNSRuleConfig>) {
    this.id = obj?.id ?? null;
    this.index = obj?.index ?? -1;
    this.name = obj?.name ?? "";
    this.enable = obj?.enable ?? true;
    this.mark = obj?.mark ? { ...obj.mark } : { t: FlowDnsMarkType.KeepGoing };
    this.source = obj?.source ?? [];
    this.resolve_mode = obj?.resolve_mode
      ? { ...obj.resolve_mode }
      : {
          t: DNSResolveModeEnum.Cloudflare,
          mode: CloudflareMode.Https,
        };
    this.flow_id = obj?.flow_id ?? 0;
    this.filter = obj?.filter ?? "unfilter";
    this.update_at = obj?.update_at ?? new Date().getTime();
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
