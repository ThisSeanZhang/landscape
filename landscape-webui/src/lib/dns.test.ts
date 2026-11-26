import { describe, expect, it } from "vitest";
import type { DnsUpstreamConfig } from "@landscape-router/types/api/schemas";
import { changeUpstreamProtocol } from "./dns";

const doh: DnsUpstreamConfig = {
  mode: { t: "https", domain: "dns.example.com", http_endpoint: "/dns-query" },
  port: 443,
  ips: ["192.0.2.1"],
  remark: "",
  enable_ip_validation: false,
};

describe("upstream protocol changes", () => {
  it("moves between protocol defaults without altering the original", () => {
    const udp = changeUpstreamProtocol(doh, "plaintext");
    expect(udp.mode).toEqual({ t: "plaintext" });
    expect(udp.port).toBe(53);
    expect(changeUpstreamProtocol(udp, "https").port).toBe(443);
    for (const next of ["tls", "quic"] as const) {
      const encrypted = changeUpstreamProtocol(doh, next);
      expect(encrypted.mode).toEqual({ t: next, domain: "dns.example.com" });
      expect(encrypted.port).toBe(853);
      expect(changeUpstreamProtocol(encrypted, "plaintext").port).toBe(53);
    }
    expect(doh.mode.t).toBe("https");
    expect(doh.port).toBe(443);
  });

  it.each([null, 8443])("preserves port %s across a manual switch", (port) => {
    expect(changeUpstreamProtocol({ ...doh, port }, "plaintext").port).toBe(
      port,
    );
  });
});
