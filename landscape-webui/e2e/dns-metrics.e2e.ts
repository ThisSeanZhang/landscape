import type { Locator, Page, Route } from "@playwright/test";
import { expect, test } from "./fixtures";

test.use({ viewport: { width: 1920, height: 1080 } });

async function expectFullContentWidth(page: Page, content: Locator) {
  const body = await page.locator(".main-body").boundingBox();
  expect(body).not.toBeNull();
  await expect
    .poll(async () => {
      const box = await content.boundingBox();
      return box
        ? Math.abs(box.x - body!.x) + Math.abs(box.width - body!.width)
        : Infinity;
    })
    .toBeLessThanOrEqual(2);
}

async function checkRefreshRetry(page: Page, endpoint: RegExp) {
  const button = page.getByRole("button", { name: /Refresh Metrics$/ });
  const reject = (route: Route) =>
    route.fulfill({ status: 503, json: { message: "test metric failure" } });
  await page.route(endpoint, reject);
  const top = await button.boundingBox();
  await button.click();
  await expect(button).toHaveAccessibleName(
    "Could not load DNS metrics · Refresh Metrics",
  );
  await expect(button).toHaveClass(/n-button--error-type/);
  await expect(
    page.getByText("test metric failure", { exact: true }),
  ).toHaveCount(0);
  await expect(page.locator(".dns-metric-page .n-alert")).toHaveCount(0);
  expect(await button.boundingBox()).toEqual(top);
  await page.unroute(endpoint, reject);
  await button.click();
  await expect(button).toHaveAccessibleName("Refresh Metrics");
  await expect(button).not.toHaveClass(/n-button--error-type/);
}

for (const [name, capabilities, store] of [
  ["memory-only build", [], {}],
  ["memory backend", ["metric_persistent"], { backend: "memory" }],
  ["default SQLite backend", ["metric_persistent"], {}],
] as const) {
  test(`DNS live and history in ${name}`, async ({ page }) => {
    await page.route("**/api/v1/system/info/capabilities", (route) =>
      route.fulfill({ json: { data: capabilities } }),
    );
    await page.route("**/api/v1/system/config/metric", (route) =>
      route.fulfill({ json: { data: { dns: { store } } } }),
    );
    await page.route("**/api/v1/flow/rules", (route) =>
      route.fulfill({
        json: {
          data:
            name === "memory-only build"
              ? []
              : [{ flow_id: 8, remark: "Guest" }],
        },
      }),
    );
    let liveRequests = 0;
    let liveFlow: string | null = null;
    let historyRequests = 0;
    let logRequests = 0;
    await page.route("**/metrics/dns/history?*", (route) => {
      expect(new URL(route.request().url()).searchParams.get("flow_id")).toBe(
        "0",
      );
      logRequests++;
      return route.fulfill({
        json: {
          data: {
            items: [
              {
                domain: "logged.example",
                flow_id: 0,
                report_time: Date.now(),
                src_ip: "192.0.2.1",
                status: "normal",
                query_type: "A",
                response_code: "NOERROR",
                duration_ms: 12,
                answers: [
                  "logged.example. 60 IN CNAME edge.example.",
                  "edge.example. 30 IN A 192.0.2.42",
                  'edge.example. 0 IN TXT "two words" "more"',
                  "2001:db8::1",
                ],
              },
            ],
            total: 1,
          },
        },
      });
    });
    await page.route(/\/metrics\/dns\/live(?:\?|$)/, (route) => {
      liveFlow = new URL(route.request().url()).searchParams.get("flow_id");
      liveRequests++;
      return route.fulfill({
        json: {
          data: {
            summary: {
              total_queries: 17,
              total_effective_queries: 12,
              cache_hit_count: 2,
              nxdomain_count: 1,
              block_count: 5,
              filter_count: 0,
              error_count: 0,
              top_domains: [{ name: "live.example", count: 17 }],
              top_blocked: [{ name: "blocked.example", count: 5 }],
              top_clients: [{ name: "192.0.2.2", count: 17 }],
              slowest_domains: [{ name: "slow.example", count: 3, value: 20 }],
            },
            minutes: [
              {
                start_ms: Date.now(),
                queries: 17,
                hits: 2,
                blocks: 5,
                errors: 0,
              },
            ],
            latency: [{ upper_ms: 50, count: 10 }],
          },
        },
      });
    });
    await page.route("**/metrics/dns/summary?*", (route) => {
      expect(new URL(route.request().url()).searchParams.get("flow_id")).toBe(
        "0",
      );
      historyRequests++;
      return route.fulfill({ json: { data: { total_queries: 0 } } });
    });
    await page.goto("/metrics/dns");
    await expect.poll(() => liveRequests).toBeGreaterThan(0);
    for (const text of [
      "live.example",
      "blocked.example",
      "slow.example",
      "192.0.2.2",
      "Query outcomes",
      "Upstream latency distribution",
      "Query volume by minute (last 5 minutes)",
    ]) {
      await expect(page.getByText(text, { exact: true })).toBeVisible();
    }
    await expectFullContentWidth(page, page.locator(".dns-dashboard"));
    if (name === "default SQLite backend")
      await checkRefreshRetry(page, /\/dns\/live(?:\?|$)/);
    expect(historyRequests).toBe(0);
    if (name !== "memory-only build") {
      await page.getByRole("textbox").click();
      await page.getByText("8 - Guest", { exact: true }).click();
      await expect.poll(() => liveFlow).toBe("8");
      await page.getByRole("textbox").click();
      await page.getByText("All", { exact: true }).click();
      await expect.poll(() => liveFlow).toBeNull();
    }
    await page.getByRole("textbox").click();
    await page.getByText("0 - Default Flow", { exact: true }).click();
    await expect.poll(() => liveFlow).toBe("0");
    await page.getByRole("radio", { name: "History", exact: true }).check();
    if (name === "default SQLite backend") {
      await expect(page.getByText("Query Log", { exact: true })).toBeVisible();
      await expect(
        page.getByText("logged.example", { exact: true }),
      ).toBeVisible();
      await expectFullContentWidth(page, page.locator(".dns-history-table"));
      const answer = page.getByRole("button", {
        name: "Show answers for logged.example",
      });
      await expect(answer).toHaveText("192.0.2.42+3");
      const beforeOpen = logRequests;
      await answer.click();
      const drawer = page.getByRole("dialog", { name: "Answer details" });
      await expect(drawer).toBeVisible();
      await expect(drawer.locator("li code")).toHaveText([
        "edge.example.",
        "192.0.2.42",
        '"two words" "more"',
        "2001:db8::1",
      ]);
      await expect(drawer.getByText("TTL 0 s")).toBeVisible();
      await expectFullContentWidth(page, page.locator(".dns-history-table"));
      await page.keyboard.press("Escape");
      await expect(drawer).toBeHidden();
      await expect(answer).toBeFocused();
      await expectFullContentWidth(page, page.locator(".dns-history-table"));
      expect(logRequests).toBe(beforeOpen);
      await checkRefreshRetry(page, /\/dns\/history\?/);
      expect(historyRequests).toBe(0);
      await page.getByText("Range Statistics", { exact: true }).click();
      await expect.poll(() => historyRequests).toBeGreaterThan(0);
      await checkRefreshRetry(page, /\/dns\/summary\?/);
      await expectFullContentWidth(page, page.locator(".dns-dashboard"));
    } else {
      if (name === "memory-only build") {
        await expect(
          page.getByText(
            "This backend build does not support persistent DNS history.",
          ),
        ).toBeVisible();
        await expect(
          page.getByRole("link", { name: "Open DNS storage settings" }),
        ).toHaveCount(0);
      } else {
        await expect(
          page.getByRole("link", { name: "Open DNS storage settings" }),
        ).toBeVisible();
      }
      expect(historyRequests).toBe(0);
      expect(logRequests).toBe(0);
    }
    const requestsBeforeSwitch = liveRequests;
    await page.getByRole("radio", { name: "Live", exact: true }).check();
    await expect.poll(() => liveRequests).toBeGreaterThan(requestsBeforeSwitch);
    if (name === "memory backend") {
      await page.route("**/api/v1/system/config/edit/metric/dns", (route) => {
        expect(route.request().method()).toBe("GET");
        return route.fulfill({
          json: { data: { config: { store }, hash: "dns" } },
        });
      });
      await page.getByRole("radio", { name: "History", exact: true }).check();
      await page
        .getByRole("link", { name: "Open DNS storage settings" })
        .click();
      await expect(page).toHaveURL(/\/config#dns-metric-config$/);
      const dnsCard = page.locator("#dns-metric-config");
      await expect(
        dnsCard.getByText("Storage backend", { exact: true }),
      ).toBeInViewport();
      const backend = dnsCard.getByText("Memory Only (MEM)", { exact: true });
      await expect(backend).toBeInViewport();
      await backend.click();
      await expect(
        page.getByText("Persistent (SQLite)", { exact: true }).last(),
      ).toBeVisible();
    }
  });
}
