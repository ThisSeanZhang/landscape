import { expect, test } from "./fixtures";

test.use({
  viewport: { width: 390, height: 844 },
  isMobile: true,
  hasTouch: true,
});

test("mobile dashboard distinguishes failed samples from zero and retains the last DNS reading", async ({
  page,
}) => {
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
  await page.route("**/api/v1/services/dhcp_v4/status", (route) =>
    route.fulfill({ json: { data: { br0: { t: "running" } } } }),
  );
  await page.goto("/");
  const member = page.getByRole("button", {
    name: /eth1.*Bridge member.*br0.*Down/,
  });
  await expect(member).toBeInViewport();
  await member.click();
  await expect(page.getByRole("heading", { name: /eth1/ })).toBeVisible();
  const services = page.getByRole("region", { name: "Service entries" });
  await expect(services).toHaveCount(0);
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: /br0.*LAN.*Bridge/ }).click();
  await expect(
    services.getByRole("button", { name: /DHCPv4.*Running/ }),
  ).toBeVisible();
  await expect(services.getByRole("button", { name: /Firewall/ })).toHaveCount(
    0,
  );
  const actions = page.getByRole("button", { name: "Actions", exact: true });
  await actions.click();
  await expect(page.getByText("Change zone", { exact: true })).toBeVisible();
  await actions.click();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Map", exact: true }).click();
  await expect(page.locator(".vue-flow")).toBeVisible();
  await page.getByRole("button", { name: "List", exact: true }).click();
  await expect(member).toBeVisible();
});

test("a phone can edit a WAN service from interface details and reopen it from the map", async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 670 });
  await page.route("**/api/v1/interfaces/all_old", (route) =>
    route.fulfill({
      json: {
        data: [
          {
            name: "eth-wan",
            index: 4,
            dev_type: "ether",
            zone_type: "wan",
            dev_status: { t: "up" },
            carrier: true,
            enable_in_boot: true,
          },
        ],
      },
    }),
  );
  const endpoint = "**/api/v1/services/wan-links";
  const link = {
    id: "aaa",
    attach_iface_name: "eth-wan",
    kind: { t: "ethernet" },
    firewall: { enable: false },
    update_at: 1,
  };
  let writes = 0;
  await page.route(endpoint, (route) =>
    route.fulfill({ json: { data: [link] } }),
  );
  await page.route(endpoint + "/status", (route) =>
    route.fulfill({
      json: {
        data: {
          aaa: {
            firewall: { t: link.firewall.enable ? "running" : "disabled" },
          },
        },
      },
    }),
  );
  await page.route(endpoint + "/aaa", (route) => {
    expect(route.request().method()).toBe("PUT");
    const payload = route.request().postDataJSON();
    expect(payload.attach_iface_name).toBe(link.attach_iface_name);
    link.firewall.enable = payload.firewall.enable;
    writes++;
    return route.fulfill({ json: { data: link } });
  });
  await page.goto("/");
  await page.getByRole("button", { name: /eth-wan.*WAN/ }).click();
  const panel = page.getByTestId("topology-detail-4");
  const services = panel.getByRole("region", { name: "Service entries" });
  const firewall = services.getByRole("button", { name: /Firewall/ });
  await expect(firewall).toContainText("Disabled");
  await expect.poll(() => panel.evaluate((el) => el.clientWidth)).toBe(320);
  await expect(services.getByRole("button", { name: /DHCPv4/ })).toHaveCount(0);
  const editor = page
    .getByRole("dialog")
    .filter({ has: page.getByRole("switch") });
  const toggle = editor.getByRole("switch", { name: "Enable", exact: true });
  await firewall.click();
  await expect(toggle).not.toBeChecked();
  await expect(editor).toBeInViewport({ ratio: 0.99 });
  await toggle.click();
  await page.keyboard.press("Escape");
  await expect(editor).toHaveCount(0);
  await expect(firewall).toContainText("Disabled");
  expect(writes).toBe(0);
  await firewall.click();
  await expect(toggle).not.toBeChecked();
  await toggle.click();
  await editor.getByRole("button", { name: "Update" }).click();
  await expect(firewall).toContainText("Running");
  expect(writes).toBe(1);
  await panel.getByRole("button", { name: "Close" }).click();
  await page.getByRole("button", { name: "Map", exact: true }).click();
  await page.getByTestId("topology-node-4-service-firewall").click();
  await expect(toggle).toBeChecked();
  await page.keyboard.press("Escape");
  await expect(editor).toHaveCount(0);
  await page
    .getByTestId("topology-node-4")
    .getByText("eth-wan", { exact: true })
    .click();
  await expect(firewall).toContainText("Running");
});

test("mobile dashboard can scroll to the last interface and back to the overview", async ({
  page,
}) => {
  const interfaces = Array.from({ length: 12 }, (_, index) => ({
    name: "eth" + index,
    index: index + 1,
    dev_type: "ether",
    dev_status: { t: "up" },
    zone_type: "lan",
    carrier: true,
    enable_in_boot: true,
  }));
  await page.route("**/api/v1/interfaces/all_old", (route) =>
    route.fulfill({ json: { data: interfaces } }),
  );
  await page.goto("/");
  const rows = page
    .getByRole("region", { name: "Network interfaces" })
    .getByRole("button");
  await expect(rows).toHaveCount(interfaces.length);
  const last = rows.last();
  const overview = page.getByRole("button", { name: "Show details" });
  await expect(overview).toBeInViewport();
  await expect(last).not.toBeInViewport();

  const touch = await page.context().newCDPSession(page);
  async function swipe(fromY: number, toY: number) {
    await touch.send("Input.dispatchTouchEvent", {
      type: "touchStart",
      touchPoints: [{ x: 180, y: fromY }],
    });
    for (let step = 1; step <= 6; step++) {
      const y = fromY + ((toY - fromY) * step) / 6;
      await touch.send("Input.dispatchTouchEvent", {
        type: "touchMove",
        touchPoints: [{ x: 180, y }],
      });
    }
    await touch.send("Input.dispatchTouchEvent", {
      type: "touchEnd",
      touchPoints: [],
    });
  }
  await swipe(710, 180);
  await expect(last).toBeInViewport({ ratio: 0.99 });
  await expect(overview).not.toBeInViewport();
  await swipe(180, 710);
  await expect(overview).toBeInViewport({ ratio: 0.99 });
  await overview.click();
  await expect(last).not.toBeInViewport();
  for (let i = 0; i < 3; i++) await swipe(710, 180);
  await expect(last).toBeInViewport({ ratio: 0.99 });
});
