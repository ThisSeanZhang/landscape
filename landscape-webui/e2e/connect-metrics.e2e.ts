import { expect, test } from "./fixtures";

test.use({ viewport: { width: 1920, height: 1080 } });

const historyRecord = (ip: string) => ({
  key: { create_time: "100000000", cpu_id: 0 },
  src_ip: ip,
  dst_ip: "192.0.2.99",
  src_port: 1234,
  dst_port: 443,
  l3_proto: 0,
  l4_proto: 6,
  flow_id: 0,
  trace_id: 0,
  ifindex: 1,
  last_report_time: Date.now(),
  total_ingress_bytes: 100,
  total_egress_bytes: 50,
  total_ingress_pkts: 2,
  total_egress_pkts: 1,
  status: 2,
  create_time_ms: 100,
  gress: 1,
});

test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/system/config/metric", (route) =>
    route.fulfill({ json: { data: { connect: { store: {} } } } }),
  );
  await page.route("**/api/v1/flow/rules", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.route("**/api/v1/metrics/connections**", (route) => {
    const path = new URL(route.request().url()).pathname;
    const data = path.endsWith("/global_stats")
      ? {
          total_connect_count: 0,
          total_ingress_bytes: 0,
          total_egress_bytes: 0,
          last_calculate_time: 0,
        }
      : path.endsWith("/history")
        ? { items: [], total: 0 }
        : [];
    return route.fulfill({ json: { data } });
  });
});

test("connection navigation keeps the IP view and URL filters across live and history", async ({
  page,
}) => {
  await page.route("**/api/v1/system/info/capabilities", (route) =>
    route.fulfill({ json: { data: ["metric_persistent"] } }),
  );
  const nav = page.getByRole("navigation", { name: "Connection Metrics" });
  const link = (name: string) => nav.getByRole("link", { name, exact: true });
  const query = "?flow_id=0&ip=192.0.2.10";
  await page.goto("/metrics/conn/src" + query);
  await expect(link("Src IP")).toHaveAttribute("aria-current", "page");
  for (const [label, path] of [
    ["History", "history-src"],
    ["Dst IP", "history-dst"],
    ["Live", "dst"],
    ["Iface", "iface"],
    ["History", "history"],
  ]) {
    await link(label).click();
    await expect(page).toHaveURL("/metrics/conn/" + path + query);
    await expect(link(label)).toHaveAttribute("aria-current", "page");
  }
  await expect(link("Iface")).toHaveCount(0);
  await expect(link("Connections")).toHaveAttribute("aria-current", "page");
  await page.goBack();
  await expect(link("Iface")).toHaveAttribute("aria-current", "page");
});

test("a build without persistence exposes all four live connection views", async ({
  page,
}) => {
  await page.route("**/api/v1/system/info/capabilities", (route) =>
    route.fulfill({ json: { data: [] } }),
  );
  await page.goto("/metrics/conn/live");
  const nav = page.getByRole("navigation", { name: "Connection Metrics" });
  await expect(nav.getByRole("link")).toHaveText([
    "Live",
    "Connections",
    "Iface",
    "Src IP",
    "Dst IP",
  ]);
});

test("memory storage links to connection settings without querying history", async ({
  page,
}) => {
  await page.route("**/api/v1/system/info/capabilities", (route) =>
    route.fulfill({ json: { data: ["metric_persistent"] } }),
  );
  await page.route("**/api/v1/system/config/metric", (route) =>
    route.fulfill({
      json: { data: { connect: { store: { backend: "memory" } } } },
    }),
  );
  let requests = 0;
  page.on("request", (req) => {
    if (req.url().includes("/metrics/connections/history")) requests++;
  });
  for (const view of ["history", "history-src", "history-dst"]) {
    await page.goto("/metrics/conn/" + view);
    await expect(
      page.getByText("Connection history is available with SQLite storage."),
    ).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Open connection storage settings" }),
    ).toHaveAttribute("href", "/config#connect-metric-config");
  }
  expect(requests).toBe(0);
  await page.route("**/api/v1/system/config/edit/metric/connect", (route) =>
    route.fulfill({
      json: {
        data: { config: { store: { backend: "memory" } }, hash: "connect" },
      },
    }),
  );
  await page
    .getByRole("link", { name: "Open connection storage settings" })
    .click();
  await expect(
    page
      .locator("#connect-metric-config")
      .getByText("Storage backend", { exact: true }),
  ).toBeInViewport();
});

test("only the latest history response sets the rows, and a failed refresh retains them", async ({
  page,
}) => {
  await page.route("**/api/v1/system/info/capabilities", (route) =>
    route.fulfill({ json: { data: ["metric_persistent"] } }),
  );
  const endpoint = /\/api\/v1\/metrics\/connections\/history(?:\?|$)/;
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  let outcome = "old";
  let started = false;
  await page.route(endpoint, async (route) => {
    if (outcome === "old") {
      started = true;
      await gate;
      return route.fulfill({
        json: { data: { items: [historyRecord("192.0.2.1")], total: 101 } },
      });
    }
    if (outcome === "error")
      return route.fulfill({ status: 503, json: { message: "failed" } });
    const items = outcome === "new" ? [historyRecord("192.0.2.2")] : [];
    return route.fulfill({ json: { data: { items, total: items.length } } });
  });
  await page.goto("/metrics/conn/history");
  await expect.poll(() => started).toBe(true);
  outcome = "new";
  // Enter a new filter while the first response is still outstanding.
  const filter = page.getByPlaceholder("Src IP", { exact: true });
  await filter.fill("192.0.2.2");
  const fresh = page.getByText("192.0.2.2:1234", { exact: true });
  await expect(fresh).toBeVisible();
  const finished = page.waitForResponse(
    (response) =>
      endpoint.test(response.url()) &&
      !new URL(response.url()).searchParams.has("src_ip"),
  );
  release();
  await finished;
  await expect(fresh).toBeVisible();
  await expect(page.locator(".n-pagination")).toHaveCount(0);
  outcome = "error";
  await page.getByRole("button", { name: "Query", exact: true }).click();
  const retry = page.getByRole("button", { name: "Query failed · Retry" });
  await expect(retry).toBeVisible();
  await expect(fresh).toBeVisible();
  outcome = "empty";
  await retry.click();
  await expect(page.getByText("No matching connections")).toBeVisible();
  await expect(retry).toHaveCount(0);
});

test("source IP history reports configuration and database failures independently", async ({
  page,
}) => {
  await page.route("**/api/v1/system/info/capabilities", (route) =>
    route.fulfill({ json: { data: ["metric_persistent"] } }),
  );
  let configFailed = true;
  await page.route("**/api/v1/system/config/metric", (route) =>
    configFailed
      ? route.fulfill({ status: 503, json: { message: "test config error" } })
      : route.fulfill({ json: { data: { connect: { store: {} } } } }),
  );
  let queries = 0;
  await page.route(/\/connections\/history\/src_ip_stats(?:\?|$)/, (route) => {
    queries++;
    return queries === 1
      ? route.fulfill({ status: 503, json: { message: "test query error" } })
      : route.fulfill({
          json: {
            data: [
              {
                ip: "192.0.2.50",
                flow_id: 0,
                connect_count: 2,
                total_egress_bytes: 100,
                total_ingress_bytes: 200,
                total_egress_pkts: 1,
                total_ingress_pkts: 2,
              },
            ],
          },
        });
  });
  await page.goto("/metrics/conn/history-src");
  await expect(
    page.getByText("Could not load connection storage settings."),
  ).toBeVisible();
  expect(queries).toBe(0);
  configFailed = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByRole("button", { name: "Query failed · Retry" }).click();
  await expect(page.getByText("192.0.2.50", { exact: true })).toBeVisible();
  expect(queries).toBe(2);
});

test("live headers sort numeric rates, source ports and durations and remember the selection", async ({
  page,
}) => {
  const now = Date.now();
  const items = Array.from({ length: 60 }, (_, i) => {
    const {
      total_ingress_bytes,
      total_egress_bytes,
      total_ingress_pkts,
      total_egress_pkts,
      ...item
    } = historyRecord("192.0.2." + (i + 1));
    return {
      ...item,
      key: { create_time: String(i + 1), cpu_id: 0 },
      src_port: [9, 100, 20][i] ?? 10,
      dst_port: 443 - i,
      last_report_time: now - i * 1000,
      create_time_ms: now - i * 1000 - ([20, 9, 100][i] ?? 10) * 1000,
      egress_bps: [12345, 120, 999][i] ?? 987,
      ingress_bps: [100, 1024, 120][i] ?? 333,
      egress_pps: 1,
      ingress_pps: 1,
    };
  });
  await page.route("**/api/v1/metrics/connections", (route) =>
    route.fulfill({ json: { data: items } }),
  );
  await page.goto("/metrics/conn/live");
  const table = page.getByRole("table", { name: "Connections" });
  const header = (name: string) =>
    table
      .getByRole("columnheader")
      .filter({ has: page.getByRole("button", { name, exact: true }) });
  const first = table.getByRole("row").nth(1);
  await expect(header("Last reported")).toHaveAttribute(
    "aria-sort",
    "descending",
  );
  await first.hover();
  await page.mouse.wheel(0, 900);
  await expect(first).not.toHaveAttribute("aria-rowindex", "2");
  await expect(header("Last reported")).toBeInViewport();
  for (const [name, direction, source] of [
    ["Egress Rate", "descending", "192.0.2.1:9"],
    ["Egress Rate", "ascending", "192.0.2.2:100"],
    ["Ingress Rate", "descending", "192.0.2.2:100"],
    ["Src Port", "descending", "192.0.2.2:100"],
    ["Duration", "descending", "192.0.2.3:20"],
  ]) {
    await header(name).getByRole("button").click();
    await expect(header(name)).toHaveAttribute("aria-sort", direction);
    await expect(first.getByRole("cell").nth(2)).toHaveText(source);
  }
  await page.reload();
  await expect(header("Duration")).toHaveAttribute("aria-sort", "descending");
  await expect(first).toContainText("192.0.2.3:20");
  await first
    .getByRole("button", { name: "Precise filter this tuple" })
    .click();
  await expect(table.getByRole("row")).toHaveCount(2);
  await expect(page.getByPlaceholder("Src IP", { exact: true })).toHaveValue(
    "192.0.2.3",
  );
});

test("history column sorting queries from page one with the selected key and order", async ({
  page,
}) => {
  await page.route("**/api/v1/system/info/capabilities", (route) =>
    route.fulfill({ json: { data: ["metric_persistent"] } }),
  );
  let query = new URLSearchParams();
  await page.route(/\/connections\/history(?:\?|$)/, (route) => {
    query = new URL(route.request().url()).searchParams;
    const ip = query.get("sort_order") === "asc" ? "192.0.2.2" : "192.0.2.1";
    return route.fulfill({
      json: { data: { items: [historyRecord(ip)], total: 85 } },
    });
  });
  await page.goto("/metrics/conn/history");
  const table = page.getByRole("table", { name: "Connections" });
  await expect(
    table.getByRole("cell", { name: "192.0.2.1:1234" }),
  ).toBeVisible();
  await page
    .locator(".n-pagination-item")
    .getByText("2", { exact: true })
    .click();
  await expect.poll(() => query.get("offset")).toBe("50");
  for (const [name, key, order] of [
    ["Total Egress", "egress", "desc"],
    ["Total Egress", "egress", "asc"],
    ["Total Ingress", "ingress", "desc"],
    ["Duration", "duration", "desc"],
    ["Src Port", "port", "desc"],
  ]) {
    await table.getByRole("button", { name, exact: true }).click();
    await expect
      .poll(() => [
        query.get("sort_key"),
        query.get("sort_order"),
        query.get("offset"),
      ])
      .toEqual([key, order, "0"]);
    await expect(
      table.getByRole("cell", {
        name: order === "asc" ? "192.0.2.2:1234" : "192.0.2.1:1234",
      }),
    ).toBeVisible();
  }
});
