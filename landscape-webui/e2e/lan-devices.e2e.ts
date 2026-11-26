import type { LanDeviceView } from "@landscape-router/types/api/schemas";
import { expect, test } from "./fixtures";

test("refreshes an empty LAN device list and shows the new DHCP lease", async ({
  page,
}) => {
  const now = Date.now();
  const device = {
    entry_id: "lan0/02:00:00:00:00:42",
    mac: "02:00:00:00:00:42",
    hostname: "test-client",
    iface_name: "lan0",
    ipv4: { ip: "192.0.2.42", source: "lease" },
    dhcp_lease: { ip: "192.0.2.42", last_request: now, expires: now + 600_000 },
    ipv6_addrs: [],
    arp_presence: Array<boolean>(24).fill(false),
    last_active: now,
    online: true,
  } satisfies LanDeviceView;
  let devices: LanDeviceView[] = [];
  const endpoint = "**/api/v1/services/lan_devices";
  await page.route(endpoint, (route) =>
    route.fulfill({ json: { data: devices } }),
  );
  await page.route("**/api/v1/devices/all", (route) =>
    route.fulfill({ json: { data: [] } }),
  );

  await page.goto("/network/lan-devices");
  const refresh = page.getByRole("button", { name: "Refresh", exact: true });
  const emptyResponse = page.waitForResponse(endpoint);
  await refresh.click();
  await emptyResponse;
  await expect(page.getByText("No LAN devices observed yet")).toBeVisible();

  devices = [
    device,
    {
      entry_id: "device-without-mac",
      hostname: "ip-only-client",
      online: false,
      last_active: now,
      ipv6_addrs: [],
      arp_presence: [],
    },
  ];
  await refresh.click();
  const row = page
    .getByRole("row")
    .filter({ has: page.getByText(device.mac, { exact: true }) });
  await expect(row.getByText(device.ipv4.ip, { exact: true })).toBeVisible();
  await expect(row.getByText("DHCP", { exact: true })).toBeVisible();
  await expect(row.getByText(device.iface_name, { exact: true })).toBeVisible();
  await expect(row.getByRole("button")).toBeEnabled();
  const ipOnlyRow = page.getByRole("row").filter({ hasText: "ip-only-client" });
  await expect(ipOnlyRow.getByRole("button")).toBeDisabled();
  await expect(page.getByText("No LAN devices observed yet")).toBeHidden();

  await page.setViewportSize({ width: 390, height: 844 });
  const name = page.getByRole("button", { name: device.hostname, exact: true });
  await expect(name).toBeInViewport();
  await expect(page.getByText(device.mac, { exact: true })).toBeHidden();
  await name.click();
  await expect(page.getByText(device.mac, { exact: true })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Add Device Binding" }).first(),
  ).toBeEnabled();
  await page.locator(".device-filters .n-select").first().click();
  await page
    .locator(".n-base-select-option")
    .getByText("lan0", { exact: true })
    .click();
  await page.locator(".device-filters .n-select").nth(1).click();
  await page
    .locator(".n-base-select-option")
    .getByText("Offline", { exact: true })
    .click();
  await expect(page.getByText("No devices match these filters")).toBeVisible();
  await page.getByRole("button", { name: "Clear filters" }).click();
  await expect(name).toBeVisible();
});
