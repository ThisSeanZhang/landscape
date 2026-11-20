import type {
  DnsUpstreamConfig,
  DNSRuleConfig,
} from "@landscape-router/types/api/schemas";
import { createFlowMark } from "./flow/default_value";

export const UPSTREAM_OPTIONS = [
  {
    label: "UDP",
    value: "plaintext",
    defaultPort: 53,
  },
  {
    label: "DoH",
    value: "https",
    defaultPort: 443,
  },
  {
    label: "DoT",
    value: "tls",
    defaultPort: 853,
  },
  {
    label: "DoQ",
    value: "quic",
    defaultPort: 853,
  },
] satisfies {
  label: string;
  value: DnsUpstreamConfig["mode"]["t"];
  defaultPort: number;
}[];

export function changeUpstreamProtocol(
  rule: DnsUpstreamConfig,
  next: DnsUpstreamConfig["mode"]["t"],
): DnsUpstreamConfig {
  if (rule.mode.t === next) return rule;
  const previous = UPSTREAM_OPTIONS.find(
    (option) => option.value === rule.mode.t,
  );
  const selected = UPSTREAM_OPTIONS.find((option) => option.value === next);
  const port =
    previous && selected && rule.port === previous.defaultPort
      ? selected.defaultPort
      : rule.port;
  const domain = rule.mode.t === "plaintext" ? "" : rule.mode.domain;
  let mode: DnsUpstreamConfig["mode"];
  switch (next) {
    case "plaintext":
      mode = { t: next };
      break;
    case "https":
      mode = { t: next, domain, http_endpoint: null };
      break;
    default:
      mode = { t: next, domain };
  }
  return { ...rule, mode, port };
}

export function upstream_mode_exhibit_name(mode: string): string {
  for (const each of UPSTREAM_OPTIONS) {
    if (each.value === mode) {
      return each.label;
    }
  }
  return mode;
}

export function createDnsRule(obj: Partial<DNSRuleConfig> = {}): DNSRuleConfig {
  return {
    id: obj?.id,
    index: obj?.index ?? -1,
    name: obj?.name ?? "",
    enable: obj?.enable ?? true,
    mark: createFlowMark(obj?.mark),
    source: obj?.source ?? [],
    flow_id: obj?.flow_id ?? 0,
    filter: obj?.filter ?? "unfilter",
    update_at: obj?.update_at,
    upstream_id: obj?.upstream_id ?? "",
  };
}
