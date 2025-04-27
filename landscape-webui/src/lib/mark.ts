import { PacketMark } from "@/rust_bindings/mark";
import { MarkType } from "./dns";

export enum FlowMarkType {
  KEEP_GOING = "keepgoing",
  DIRECT = "direct",
  DROP = "drop",
  REDIRECT = "redirect",
  ALLOW_REUSE_PORT = "allowreuseport",
}

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

import type {
  FlowDnsMark,
  WanIPRuleConfig,
  WanIPRuleSource,
} from "@/rust_bindings/flow";
export class WanIPRuleConfigClass implements WanIPRuleConfig {
  id: string;
  index: number;
  enable: boolean;
  mark: FlowDnsMark;
  source: WanIPRuleSource[];
  remark: string;
  flow_id: number;
  override_dns: boolean;

  constructor(obj: Partial<WanIPRuleConfig> = {}) {
    this.id = obj?.id ?? "";
    this.index = obj?.index ?? -1;
    this.enable = obj?.enable ?? true;
    this.mark = obj?.mark ? { ...obj.mark } : { t: FlowMarkType.KEEP_GOING };
    this.source = obj?.source ? obj?.source.map(new_wan_rules) : [];
    this.remark = obj?.remark ?? "";
    this.flow_id = obj?.flow_id ?? 0;
    this.override_dns = obj?.override_dns ?? false;
  }
}

export function new_wan_rules(e: any): WanIPRuleSource {
  if (e.t == "config") {
    return { t: "config", ip: e.ip, prefix: e.prefix };
  } else {
    return { t: "geokey", country_code: e.key };
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
  local_port: string | undefined;
  address: string | undefined;
  ip_prefixlen: number;

  constructor(obj?: {
    ip_protocol?: IPProtocol;
    local_port?: string | undefined;
    address?: string | undefined;
    ip_prefixlen?: number;
  }) {
    this.ip_protocol = obj?.ip_protocol ?? IPProtocol.TCP;
    this.local_port = obj?.local_port ?? "80";
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

export enum ICMPTypes {
  EchoReply = 0,
  DestinationUnreachable = 3,
  SourceQuench = 4,
  RedirectMessage = 5,
  EchoRequest = 8,
  RouterAdvertisement = 9,
  RouterSolicitation = 10,
  TimeExceeded = 11,
  ParameterProblem = 12,
  Timestamp = 13,
  TimestampReply = 14,
  InformationRequest = 15,
  InformationReply = 16,
  AddressMaskRequest = 17,
  AddressMaskReply = 18,
  Traceroute = 30,
  DatagramConversionError = 31,
  MobileHostRedirect = 32,
  WhereAreYou = 33,
  HereIAm = 34,
  MobileRegistrationRequest = 35,
  MobileRegistrationReply = 36,
  DomainNameRequest = 37,
  DomainNameReply = 38,
  SkipAlgorithmDiscoveryProtocol = 39,
  Photuris = 40,
  ExperimentalMobilityProtocols = 41,
  ExtendedEchoRequest = 42,
  ExtendedEchoReply = 43,
  Experimental1 = 253,
  Experimental2 = 254,
}

export enum ICMP6Types {
  DestinationUnreachable = 1,
  PacketTooBig = 2,
  TimeExceeded = 3,
  ParameterProblem = 4,
  PrivateExperimentation1 = 100,
  PrivateExperimentation2 = 101,
  ReservedExpansion = 127,
  EchoRequest = 128,
  EchoReply = 129,
  MulticastListenerQuery = 130,
  MulticastListenerReport = 131,
  MulticastListenerDone = 132,
  RouterSolicitation = 133,
  RouterAdvertisement = 134,
  NeighborSolicitation = 135,
  NeighborAdvertisement = 136,
  RedirectMessage = 137,
  RouterRenumbering = 138,
  NodeInformationQuery = 139,
  NodeInformationResponse = 140,
  InverseNeighborDiscoverySolicitation = 141,
  InverseNeighborDiscoveryAdvertisement = 142,
  MulticastListenerDiscoveryReports = 143,
  HomeAgentAddressDiscoveryRequest = 144,
  HomeAgentAddressDiscoveryReply = 145,
  MobilePrefixSolicitation = 146,
  MobilePrefixAdvertisement = 147,
  CertificationPathSolicitation = 148,
  CertificationPathAdvertisement = 149,
  MulticastRouterAdvertisement = 151,
  MulticastRouterSolicitation = 152,
  MulticastRouterTermination = 153,
  RplControlMessage = 155,
  ExtendedEchoRequest = 160,
  ExtendedEchoReply = 161,
  PrivateExperimentation3 = 200,
  PrivateExperimentation4 = 201,
  ReservedExpansion2 = 255,
}

export function icmp_options(): { label: string; value: number }[] {
  return [
    { label: "Echo Reply", value: ICMPTypes.EchoReply },
    {
      label: "Destination Unreachable",
      value: ICMPTypes.DestinationUnreachable,
    },
    { label: "Source Quench", value: ICMPTypes.SourceQuench },
    { label: "Redirect Message", value: ICMPTypes.RedirectMessage },
    { label: "Echo Request", value: ICMPTypes.EchoRequest },
    { label: "Router Advertisement", value: ICMPTypes.RouterAdvertisement },
    { label: "Router Solicitation", value: ICMPTypes.RouterSolicitation },
    { label: "Time Exceeded", value: ICMPTypes.TimeExceeded },
    { label: "Parameter Problem", value: ICMPTypes.ParameterProblem },
    { label: "Timestamp", value: ICMPTypes.Timestamp },
    { label: "Timestamp Reply", value: ICMPTypes.TimestampReply },
    { label: "Information Request", value: ICMPTypes.InformationRequest },
    { label: "Information Reply", value: ICMPTypes.InformationReply },
    { label: "Address Mask Request", value: ICMPTypes.AddressMaskRequest },
    { label: "Address Mask Reply", value: ICMPTypes.AddressMaskReply },
    { label: "Traceroute", value: ICMPTypes.Traceroute },
    {
      label: "Datagram Conversion Error",
      value: ICMPTypes.DatagramConversionError,
    },
    { label: "Mobile Host Redirect", value: ICMPTypes.MobileHostRedirect },
    { label: "Where Are You", value: ICMPTypes.WhereAreYou },
    { label: "Here I Am", value: ICMPTypes.HereIAm },
    {
      label: "Mobile Registration Request",
      value: ICMPTypes.MobileRegistrationRequest,
    },
    {
      label: "Mobile Registration Reply",
      value: ICMPTypes.MobileRegistrationReply,
    },
    { label: "Domain Name Request", value: ICMPTypes.DomainNameRequest },
    { label: "Domain Name Reply", value: ICMPTypes.DomainNameReply },
    {
      label: "Skip Algorithm Discovery Protocol",
      value: ICMPTypes.SkipAlgorithmDiscoveryProtocol,
    },
    { label: "Photuris", value: ICMPTypes.Photuris },
    {
      label: "Experimental Mobility Protocols",
      value: ICMPTypes.ExperimentalMobilityProtocols,
    },
    { label: "Extended Echo Request", value: ICMPTypes.ExtendedEchoRequest },
    { label: "Extended Echo Reply", value: ICMPTypes.ExtendedEchoReply },
    { label: "Experimental1", value: ICMPTypes.Experimental1 },
    { label: "Experimental2", value: ICMPTypes.Experimental2 },
  ];
}

export function icmp6_options(): { label: string; value: number }[] {
  return [
    {
      label: "Destination Unreachable",
      value: ICMP6Types.DestinationUnreachable,
    },
    { label: "Packet Too Big", value: ICMP6Types.PacketTooBig },
    { label: "Time Exceeded", value: ICMP6Types.TimeExceeded },
    { label: "Parameter Problem", value: ICMP6Types.ParameterProblem },
    { label: "Echo Request", value: ICMP6Types.EchoRequest },
    { label: "Echo Reply", value: ICMP6Types.EchoReply },
    {
      label: "Multicast Listener Query",
      value: ICMP6Types.MulticastListenerQuery,
    },
    {
      label: "Multicast Listener Report",
      value: ICMP6Types.MulticastListenerReport,
    },
    {
      label: "Multicast Listener Done",
      value: ICMP6Types.MulticastListenerDone,
    },
    { label: "Router Solicitation", value: ICMP6Types.RouterSolicitation },
    { label: "Router Advertisement", value: ICMP6Types.RouterAdvertisement },
    { label: "Neighbor Solicitation", value: ICMP6Types.NeighborSolicitation },
    {
      label: "Neighbor Advertisement",
      value: ICMP6Types.NeighborAdvertisement,
    },
    { label: "Redirect Message", value: ICMP6Types.RedirectMessage },
    { label: "Router Renumbering", value: ICMP6Types.RouterRenumbering },
    { label: "Node Information Query", value: ICMP6Types.NodeInformationQuery },
    {
      label: "Node Information Response",
      value: ICMP6Types.NodeInformationResponse,
    },
    {
      label: "Inverse Neighbor Discovery Solicitation",
      value: ICMP6Types.InverseNeighborDiscoverySolicitation,
    },
    {
      label: "Inverse Neighbor Discovery Advertisement",
      value: ICMP6Types.InverseNeighborDiscoveryAdvertisement,
    },
    {
      label: "Multicast Listener Discovery Reports",
      value: ICMP6Types.MulticastListenerDiscoveryReports,
    },
    {
      label: "Home Agent Address Discovery Request",
      value: ICMP6Types.HomeAgentAddressDiscoveryRequest,
    },
    {
      label: "Home Agent Address Discovery Reply",
      value: ICMP6Types.HomeAgentAddressDiscoveryReply,
    },
    {
      label: "Mobile Prefix Solicitation",
      value: ICMP6Types.MobilePrefixSolicitation,
    },
    {
      label: "Mobile Prefix Advertisement",
      value: ICMP6Types.MobilePrefixAdvertisement,
    },
    {
      label: "Certification Path Solicitation",
      value: ICMP6Types.CertificationPathSolicitation,
    },
    {
      label: "Certification Path Advertisement",
      value: ICMP6Types.CertificationPathAdvertisement,
    },
    {
      label: "Multicast Router Advertisement",
      value: ICMP6Types.MulticastRouterAdvertisement,
    },
    {
      label: "Multicast Router Solicitation",
      value: ICMP6Types.MulticastRouterSolicitation,
    },
    {
      label: "Multicast Router Termination",
      value: ICMP6Types.MulticastRouterTermination,
    },
    { label: "RPL Control Message", value: ICMP6Types.RplControlMessage },
    { label: "Extended Echo Request", value: ICMP6Types.ExtendedEchoRequest },
    { label: "Extended Echo Reply", value: ICMP6Types.ExtendedEchoReply },
    {
      label: "Private Experimentation 1",
      value: ICMP6Types.PrivateExperimentation1,
    },
    {
      label: "Private Experimentation 2",
      value: ICMP6Types.PrivateExperimentation2,
    },
    {
      label: "Private Experimentation 3",
      value: ICMP6Types.PrivateExperimentation3,
    },
    {
      label: "Private Experimentation 4",
      value: ICMP6Types.PrivateExperimentation4,
    },
    { label: "Reserved Expansion", value: ICMP6Types.ReservedExpansion },
    { label: "Reserved Expansion 2", value: ICMP6Types.ReservedExpansion2 },
  ];
}
