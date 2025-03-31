export class DnsRule {
  index: number;
  name: string;
  enable: boolean;
  mark: PacketMark;
  source: RuleSource[];
  resolve_mode: DNSResolveMode;

  constructor(obj?: {
    index?: number;
    name?: string;
    enable?: boolean;
    mark?: PacketMark;
    source?: RuleSource[];
    resolve_mode?: DNSResolveMode;
  }) {
    this.index = obj?.index ?? -1;
    this.name = obj?.name ?? "";
    this.enable = obj?.enable ?? true;
    this.mark = obj?.mark ? { ...obj.mark } : { t: MarkType.NoMark };
    this.source = obj?.source ?? [];
    this.resolve_mode = obj?.resolve_mode
      ? { ...obj.resolve_mode }
      : {
          t: DNSResolveModeEnum.CloudFlare,
          mode: CloudFlareMode.Tls,
        };
  }
}

export enum DomainMatchType {
  Plain = "plain",
  Regex = "regex",
  Domain = "domain",
  Full = "full",
}

export type RuleSource =
  | { t: "geokey"; key: string }
  | { t: "config"; match_type: DomainMatchType; value: string };

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

export function get_dns_resolve_mode_options(): {
  label: string;
  value: string;
}[] {
  return [
    { label: "重定向", value: DNSResolveModeEnum.Redirect },
    { label: "自定义上游", value: DNSResolveModeEnum.Upstream },
    { label: "CloudFlare", value: DNSResolveModeEnum.CloudFlare },
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
  CloudFlare = "cloudflare",
}

export enum DnsUpstreamTypeEnum {
  Plaintext = "plaintext",
  Tls = "tls",
  Https = "https",
}

export enum CloudFlareMode {
  Plaintext = "plaintext",
  Tls = "tls",
  Https = "https",
}

export type DnsUpstreamType =
  | { t: DnsUpstreamTypeEnum.Plaintext }
  | { t: DnsUpstreamTypeEnum.Tls; domain: string }
  | { t: DnsUpstreamTypeEnum.Https; domain: string };

export type DNSResolveMode =
  | { t: DNSResolveModeEnum.Redirect; ips: string[] }
  | DnsUpstreamMode
  | { t: DNSResolveModeEnum.CloudFlare; mode: CloudFlareMode };

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
