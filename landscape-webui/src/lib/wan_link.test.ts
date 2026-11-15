import { describe, expect, it } from "vitest";
import type { WanLinkConfig } from "@landscape-router/types/api/schemas";
import { default_health_check, wan_link_from_payload } from "./wan_link";

describe("health probe family switches", () => {
  it("preserves explicit opt-outs when loading and serializing WAN settings", () => {
    for (const [v4, v6] of [
      [true, false],
      [false, true],
      [false, false],
    ]) {
      const payload = {
        attach_iface_name: "wan-test",
        health_check: {
          ...default_health_check(),
          ipv4_probe_enabled: v4,
          ipv6_probe_enabled: v6,
        },
      } as WanLinkConfig;
      const link = wan_link_from_payload(payload);
      const saved = JSON.parse(JSON.stringify(link));
      expect(saved.health_check.ipv4_probe_enabled).toBe(v4);
      expect(saved.health_check.ipv6_probe_enabled).toBe(v6);
      expect(saved.health_check.probe).toEqual(payload.health_check!.probe);
    }
  });
  it("keeps both probe switches on for old payloads without new fields", () => {
    const payload = {
      attach_iface_name: "wan-test",
      health_check: { enable: false },
    } as WanLinkConfig;
    const health = wan_link_from_payload(payload).health_check;
    expect(health.ipv4_probe_enabled).toBe(true);
    expect(health.ipv6_probe_enabled).toBe(true);
  });
});
