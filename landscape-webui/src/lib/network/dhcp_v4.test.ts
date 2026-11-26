import { expect, it } from "vitest";
import { createDhcpV4Config } from "./dhcp_v4";

it("fills form defaults using the saved subnet and preserves explicit settings", () => {
  const saved = createDhcpV4Config("lan0");
  expect(saved.config.ip_range_start).toBe("192.168.5.2");
  const form = createDhcpV4Config("lan0", {
    ...saved,
    enable: false,
    update_at: 12,
    config: {
      ...saved.config,
      server_ip_addr: "10.0.0.1",
      network_mask: 28,
      ip_range_start: "10.0.0.4",
      ip_range_end: null,
      address_lease_time: 3600,
    },
  });
  expect(form.enable).toBe(false);
  expect(form.update_at).toBe(12);
  expect(form.config).toMatchObject({
    ip_range_start: "10.0.0.4",
    ip_range_end: "10.0.0.15",
    address_lease_time: 3600,
    custom_options: [],
  });
});
