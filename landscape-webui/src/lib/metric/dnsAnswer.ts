import type { DnsMetric } from "@landscape-router/types/api/schemas";

export interface DnsAnswer {
  name?: string;
  ttl?: string;
  dnsClass?: string;
  type?: string;
  value: string;
}

export type DnsLogEntry = DnsMetric & {
  rowIndex: number;
  records: DnsAnswer[];
};

// Hickory formats a record as "owner TTL class type RDATA". Keep RDATA intact,
// including quoted text, and retain legacy values without a record header.
export function parseDnsAnswer(raw: string): DnsAnswer {
  const fields =
    /^((?:\\.|[^\s\\])+)\s+(\d+)\s+(IN|CH|HS|NONE|ANY|OPT|UNKNOWN|CLASS\d+)\s+(\S+)\s+([\s\S]*)$/.exec(
      raw,
    );
  if (!fields) return { value: raw };
  const [, name, ttl, dnsClass, type, value] = fields;
  return { name, ttl, dnsClass, type, value };
}
