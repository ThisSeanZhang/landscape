import { expect, test } from "./fixtures";

test("mobile dashboard distinguishes failed samples from zero and retains the last DNS reading", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  let failed = true;
  await page.route("**/api/v1/system/info/interval", (route) =>
    failed
      ? route.fulfill({ status: 503, json: {} })
      : route.fulfill({ json: { data: { global_cpu_info: 0 } } }),
  );
  await page.route("**/api/v1/metrics/dns/summary/lightweight**", (route) =>
    failed
      ? route.fulfill({ status: 503, json: {} })
      : route.fulfill({ json: { data: { total_queries: 42 } } }),
  );
  await page.goto("/");
  const cpu = page
    .locator("#overview-cards .n-card")
    .filter({ has: page.getByText("CPU", { exact: true }) });
  const dns = page.locator(".dns-status-card");
  await expect(cpu.getByText("Sample failed")).toBeVisible();
  await expect(cpu.getByText("0.0%")).toHaveCount(0);
  await expect(dns.getByText("Sample failed")).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Network interfaces" }),
  ).toBeInViewport();

  failed = false;
  await cpu.getByRole("button", { name: "Retry" }).click();
  await expect(cpu.getByText("0.0%", { exact: true })).toBeVisible();
  await dns.getByRole("button", { name: "Retry" }).click();
  await expect(dns.getByText("42", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Show details" }).click();
  await expect(cpu.getByText("Average Load", { exact: true })).toBeVisible();

  failed = true;
  await dns.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(dns.getByText("Sample failed")).toBeVisible();
  await expect(dns.getByText(/Updated At/)).toBeVisible();
  await page.getByRole("button", { name: "Hide details" }).click();
  await expect(dns.getByText("42", { exact: true })).toBeVisible();
});

test("mobile interface list opens a bridge member and allows switching to the topology", async ({
  page,
}) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.route("**/api/v1/interfaces/all_old", (route) =>
    route.fulfill({
      json: {
        data: [
          {
            name: "br0",
            index: 2,
            dev_kind: "bridge",
            zone_type: "lan",
            dev_type: "ether",
            dev_status: { t: "up" },
            carrier: true,
            enable_in_boot: true,
          },
          {
            name: "eth1",
            index: 3,
            controller_id: 2,
            dev_status: { t: "down" },
            zone_type: "undefined",
            dev_type: "ether",
            carrier: false,
            enable_in_boot: true,
          },
        ],
      },
    }),
  );
  await page.goto("/");
  const member = page.getByRole("button", {
    name: /eth1.*Bridge member.*br0.*Down/,
  });
  await expect(member).toBeInViewport();
  await member.click();
  await expect(page.getByRole("heading", { name: /eth1/ })).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Map", exact: true }).click();
  await expect(page.locator(".vue-flow")).toBeVisible();
  await page.getByRole("button", { name: "List", exact: true }).click();
  await expect(member).toBeVisible();
});
